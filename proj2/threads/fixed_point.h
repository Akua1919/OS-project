#ifndef __THREAD_FIXED_POINT_H
#define __THREAD_FIXED_POINT_H

/* Basic definitions of fixed point. */
#define fixed (1<<16)
/* Convert n to fixed point:	n * f  */
#define Convert(n) ( n * fixed )
/* Convert x to integer (rounding toward zero):	x / f  */
#define Convert2(x) ( x / fixed )
/* Convert x to integer (rounding to nearest):	(x + f / 2) / f if x >= 0,  (x - f / 2) / f if x <= 0. */
#define Convert3(x) ( x >= 0 ? ( x + fixed / 2) / fixed : ( x - fixed / 2) / fixed )
/* Add x and y:	x + y */
#define ADD_X_Y(x,y) ( x + y )
/* Subtract y from x:	x - y */
#define SUB_X_Y(x,y) ( x - y )
/* Add x and n:	x + n * f */
#define ADD_X_N(x,n) ( x + n*fixed )
/* Subtract n from x:	x - n * f */
#define SUB_X_N(x,n) ( x - n*fixed )
/* Multiply x by y:	((int64_t) x) * y / f  */
#define MUL_X_Y(x,y) ( 	((int64_t) x ) * y / fixed )
/* Multiply x by n:	x * n */
#define MUL_X_N(x,n) ( x * n)
/* Divide x by y:	((int64_t) x) * f / y */
#define DIV_X_Y(x,y) ( ((int64_t) x) * fixed / y )
/* Divide x by n:	x / n */
#define DIV_X_N(x,n) ( x / n)

#endif
