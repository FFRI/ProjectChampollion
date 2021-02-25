//
// (c) FFRI Security, Inc., 2020 / Author: FFRI Security, Inc.
//
#include <stdio.h>

__attribute__((noinline))
int int_arguments(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11, int a12) {
    return a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10 + a11 + a12;
}

__attribute__((noinline))
double double_arguments(double a1, double a2, double a3, double a4, double a5, double a6, double a7, double a8, double a9, double a10, double a11, double a12) {
    return a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10 + a11 + a12;
}

int main() {
    const int sum_int = int_arguments(1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2);
    const double sum_double = double_arguments(1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2);
    printf("%f %d\n", sum_double, sum_int);
}
