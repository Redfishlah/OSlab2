// sam 0426

#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define p 17
#define q 14
// #define f (1<<q)
#define factor (1<<q)


#define CONVERT_N_TO_FIXED_POINT(n)             ((n)*(factor))
#define CONVERT_X_TO_INTEGER_ZERO(x)            ((x)/(factor))
#define CONVERT_X_TO_INTEGER_NEAREST(x)         (((x)>=0)?(((x)+(factor)/2)/(factor)):(((x)-(factor)/2)/(factor)))

#define ADD_X_AND_Y(x,y)                        ((x)+(y))
#define SUBTRACT_Y_FROM_X(x,y)                  ((x)-(y))
#define ADD_X_AND_N(x,n)                        ((x)+(n)*(factor))
#define SUBTRACT_N_FROM_X(x,n)                  ((x)-(n)*(factor))
#define MULTIPLY_X_BY_Y(x,y)                    (((int64_t) (x))*(y)/(factor))
#define MULTIPLY_X_BY_N(x,n)                    ((x)*(n))
#define DIVIDE_X_BY_Y(x,y)                      (((int64_t) (x))*(factor)/(y))
#define DIVIDE_X_BY_N(x,n)                      ((x)/(n))

#endif