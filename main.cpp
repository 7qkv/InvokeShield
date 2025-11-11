#include <stdio.h>
#include "invokeshield.hpp"

int add(int x, int y) {
    return x + y;
}

int multiply(int a, int b) {
    return a * b;
}

double divide(double n, double d) {
    return d != 0 ? n / d : 0;
}

int main() {
    printf("=== InvokeShield ===\n\n");
    
    int r1 = IVS_CALL(int, add, 10, 5);
    printf("Basic: %d\n", r1);
    
    int r2 = IVS_PROTECTED(int, multiply, 7, 8);
    printf("Protected: %d\n", r2);
    
    int r3 = IVS_SECURE(int, add, 15, 3);
    printf("Secure: %d\n", r3);
    
    int r4 = IVS_INDIRECT(int, multiply, 4, 9);
    printf("Indirect: %d\n", r4);
    
    int r5 = IVS_FORTIFIED(int, add, 100, 50);
    printf("Fortified: %d\n", r5);
    
    int r6 = IVS_ARMORED(int, multiply, 12, 3);
    printf("Armored: %d\n", r6);
    
    int r7 = IVS_STEALTH(int, add, 25, 25);
    printf("Stealth: %d\n", r7);
    
    int r8 = IVS_LAYERED(int, multiply, 6, 7);
    printf("Layered: %d\n", r8);
    
    double r9 = IVS_ULTIMATE(double, divide, 100.0, 4.0);
    printf("Ultimate: %.2f\n", r9);
    
    printf("\nDone.\n");
    return 0;
}
