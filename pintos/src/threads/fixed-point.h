#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define P 17
#define Q 14
#define F (1 << (Q))

#define TO_FIXED_POINT(n) ((n)*(F))

#define TO_INT_ROUNDED_NEAREST(x) ((x) >= 0) ? (((x)+((F)/2))/(F)) : (((x)-((F)/2))/(F))

#define ADD(x,y) ((x) + (y))
#define SUB(x,y) ((x) - (y))
#define MUL(x,y) (((int64_t)x) * (y)/(F))
#define DIV(x,y) (((int64_t)x) * (F)/(y))

#define ADD_INTEGER(x, n) ((x) + (n) * (F))
#define SUB_INTEGER(x, n) ((x) - (n) * (F))
#define MUL_INTEGER(x, n) ((x) * (n))
#define DIV_INTEGER(x, n) ((x) / (n))

#endif /* threads/fixed-point.h */
