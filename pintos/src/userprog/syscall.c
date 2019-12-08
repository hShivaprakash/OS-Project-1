#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "../devices/shutdown.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int);
pid_t exec (const char *);
int wait (pid_t);
bool create (const char *, unsigned);
bool remove (const char *);
int open (const char *);
int filesize (int);
int read (int, void *, unsigned);
int write (int, const void *, unsigned);
void seek (int, unsigned);
unsigned tell (int);
void close (int);
bool are_addresses_valid(void *, void *, void *, void *);
bool is_address_valid(void *addr);
struct file * get_file_ptr_using_fd (int);

struct lock mutex;


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&mutex);
}

void 
halt (void) {
  shutdown_power_off();
}

void 
exit (int status) {
  struct thread *t = thread_current();
  struct fdesc *file_desc_map;
  struct list_elem *e;
  struct thread *parent;
  struct child_status *c;
 
  parent = find_thread_by_id(t->parent);
  printf ("%s: exit(%d)\n",t->name, status);
  
  if(parent != NULL) {
    c = malloc(sizeof(struct child_status));
    c->status = status;
    c->child_id = t->tid;
    list_push_back(&parent->child_list, &c->elem);
    if(parent->exec_call == NOT_EXEC_CALL || parent->exec_call == EXEC_DONE)
      customized_sema_up(&blocker);
  }

  if(!list_empty(&t->fd_mapper_list)) {
    lock_acquire(&mutex);
    while(!list_empty(&t->fd_mapper_list)) {
      file_desc_map = list_entry(list_pop_back(&t->fd_mapper_list), struct fdesc, elem);
      file_close(file_desc_map->fptr);
      free(file_desc_map);
    }
    lock_release(&mutex);
  }
  
  thread_exit();
}

pid_t 
exec (const char *cmd_line) {
  char *ptr_file;
  pid_t exec_id;
  struct thread *t = thread_current();
  if(!is_address_valid(cmd_line))
    exit(-1);
  t->exec_call = EXEC_CALL;
  exec_id = process_execute(cmd_line);
  sema_down(&blocker);
  if(t->exec_call == EXEC_LOAD_SUCCESS)
    return exec_id;
  t->exec_call = EXEC_DONE;
  return -1;
}

int 
wait (pid_t pid) {
  return process_wait(pid);
}

bool 
create (const char *file, unsigned initial_size) {
  if(!is_address_valid(file))
    exit(-1);
  lock_acquire(&mutex);
  bool create_status = filesys_create(file, initial_size);
  lock_release(&mutex);
  return create_status;
}

bool 
remove (const char *file) {
  if(!is_address_valid(file))
    exit(-1);
  lock_acquire(&mutex);
  bool remove_status = filesys_remove(file);
  lock_release(&mutex);
  return remove_status;
}

int 
open (const char *file) {
  struct file *file_ptr;
  struct thread *t = thread_current();
  struct fdesc *file_desc;

  if(!is_address_valid(file))
  {
    exit(-1);
    return -1;
  }
  lock_acquire(&mutex);
  file_ptr = filesys_open(file);
  lock_release(&mutex);
  if(file_ptr != NULL) {
    file_desc = malloc(sizeof(struct fdesc));
    file_desc->fptr = file_ptr;
    if(list_empty(&t->fd_mapper_list)) {
      file_desc->fd_value = 2;
    } else {
      file_desc->fd_value = list_entry(list_back(&t->fd_mapper_list), struct fdesc, elem)->fd_value + 1;
    }
    list_push_back(&t->fd_mapper_list, &file_desc->elem);
    return file_desc->fd_value; 
  }
  return -1;
 
}

int 
filesize (int fd) {
  struct file *fptr;
  int32_t file_size;

  fptr = get_file_ptr_using_fd(fd);
  
  if(fptr != NULL) {
    lock_acquire(&mutex);
    file_size = file_length(fptr);
    lock_release(&mutex);
    return file_size;
  }
  return -1;
}

int 
read (int fd, void *buffer, unsigned size) {
  struct file *fptr;
  int bytes_read = 0;
  
  if(!is_address_valid(buffer)) {
    exit(-1);
    return -1;
  } else if(fd == STDOUT_FILENO) {
    return -1;
  } else if(fd == STDIN_FILENO) {
    return input_getc();
  } else {
    fptr = get_file_ptr_using_fd(fd);
    if(fptr != NULL) {
      lock_acquire(&mutex);
      bytes_read = file_read(fptr, buffer, size);
      lock_release(&mutex);
      return bytes_read;
    }
    return -1;
  }
}

int 
write (int fd, const void *buffer, unsigned size) {
  struct file *fptr;
  int bytes_written = 0;
  if(!is_address_valid(buffer)) {
    exit(-1);
  } else if(fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return 1;
  } else if(fd == STDIN_FILENO) {
    return -1;
  } else {
    fptr = get_file_ptr_using_fd(fd);
    if(fptr != NULL) {
      lock_acquire(&mutex);
      bytes_written = file_write(fptr, buffer, size);
      lock_release(&mutex);
      return bytes_written;
    }
    return -1;
  }
}

void 
seek (int fd, unsigned position) {
  struct file *fptr;
  
  fptr = get_file_ptr_using_fd(fd);

  if(fptr != NULL) {
    lock_acquire(&mutex);
    file_seek(fptr, position);
    lock_release(&mutex);
  }
}

unsigned
tell (int fd) {
  struct file *fptr;
  int32_t curr_pos = 0;
  
  fptr = get_file_ptr_using_fd(fd);

  if(fptr != NULL) {
    lock_acquire(&mutex);
    curr_pos = file_tell(fptr);
    lock_release(&mutex);
  }
  return -1;
}

void 
close (int fd) {
  struct thread *t = thread_current();
  struct fdesc *file_desc_map;
  struct list_elem *e;

  if(!list_empty(&t->fd_mapper_list)) {
    e = list_begin(&t->fd_mapper_list);

    while(e != list_end(&t->fd_mapper_list)) {
      file_desc_map = list_entry(e, struct fdesc, elem);
      if(file_desc_map->fd_value == fd) {
        lock_acquire(&mutex);
        file_close(file_desc_map->fptr);
        list_remove(e);
        free(file_desc_map);
        lock_release(&mutex);
        break;
      }
      e = list_next(e);
    }
  }
}

bool are_addresses_valid(void *addr, void *addr1, void *addr2, void *addr3) {
  return (
    (addr !=NULL && is_user_vaddr(addr) && (pagedir_get_page(thread_current()->pagedir, addr) != NULL)) &&
    (addr1 !=NULL && is_user_vaddr(addr1) && (pagedir_get_page(thread_current()->pagedir, addr1) != NULL)) &&
    (addr2 !=NULL && is_user_vaddr(addr2) && (pagedir_get_page(thread_current()->pagedir, addr2) != NULL)) &&
    (addr3 !=NULL && is_user_vaddr(addr3) && (pagedir_get_page(thread_current()->pagedir, addr3) != NULL))
  );
}

bool is_address_valid(void *addr) {
  return (
    (addr !=NULL && is_user_vaddr(addr) && (pagedir_get_page(thread_current()->pagedir, addr) != NULL)
    && addr > (void *)0x08048000)
  );
}

struct file * get_file_ptr_using_fd (int fd) {
  struct thread *t = thread_current();
  struct list_elem *e  = list_begin(&t->fd_mapper_list);
  struct fdesc *file_desc_map;

  if(!list_empty(&t->fd_mapper_list)) {
    while(e != list_end(&t->fd_mapper_list)) {
      file_desc_map = list_entry(e, struct fdesc, elem);
      if(file_desc_map->fd_value == fd)
        return file_desc_map->fptr;
      e = list_next(e);
    }
  }
  return NULL;
}

static void
syscall_handler (struct intr_frame *f) 
{
  int *esp = f->esp;
  if(!are_addresses_valid(esp, esp+1, esp+2, esp+3)) {
    exit(-1);
  }
  switch (*esp) {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      exit(*(esp + 1));
      break;

    case SYS_EXEC:
      f->eax = exec((char *) *(esp + 1));
      break;

    case SYS_WAIT:
      f->eax = wait(*(esp + 1));
      break;

    case SYS_CREATE:
      f->eax = create((char *) *(esp + 1), *(esp + 2));
      break;

    case SYS_REMOVE:
      f->eax = remove((char *) *(esp + 1));
      break;

    case SYS_OPEN:
      f->eax = open((char *) *(esp + 1));
      break;

    case SYS_FILESIZE:
      f->eax = filesize(*(esp + 1));
      break;

    case SYS_READ:
      f->eax = read(*(esp + 1), (void *) *(esp + 2), *(esp + 3));
      break;

    case SYS_WRITE:
      f->eax = write(*(esp + 1), (void *) *(esp + 2), *(esp + 3));
      break;

    case SYS_SEEK:
      seek(*(esp + 1), *(esp + 2));
      break;

    case SYS_TELL:
      f->eax = tell(*(esp + 1));
      break;

    case SYS_CLOSE:
      close(*(esp + 1));
      break;

    default:
      break;
  }
}
