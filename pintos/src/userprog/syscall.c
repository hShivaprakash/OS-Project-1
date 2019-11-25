#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void 
halt (void) {
  printf ("halt System call!\n");
}

void 
exit (int status) {
  printf ("exit System call!\n");
}

pid_t 
exec (const char *cmd_line) {
  printf ("exec System call!\n");
  return 1;
}

int 
wait (pid_t pid) {
  printf ("wait System call!\n");
  return 1;
}

bool 
create (const char *file, unsigned initial_size) {
  printf ("create System call!\n");
  return true;
}

bool 
remove (const char *file) {
  printf ("remove System call!\n");
  return true;
}

int 
open (const char *file) {
  printf ("open System call!\n");
  return 1;
}

int 
filesize (int fd) {
  printf ("filesize System call!\n");
  return 1;
}

int 
read (int fd, void *buffer, unsigned size) {
  printf ("read System call!\n");
  return 1;
}

int 
write (int fd, const void *buffer, unsigned size) {
  printf ("write System call!\n");
  return 1;
}

void 
seek (int fd, unsigned position) {
  printf ("seek System call!\n");
}

unsigned 
tell (int fd) {
  printf ("tell System call!\n");
  return fd;
} 

void 
close (int fd) {
  printf ("close System call!\n");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  int *esp = f->esp;
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
  //thread_exit ();

}
