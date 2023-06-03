#include "test.hpp"

int main() {
    volatile int n = 0;
    n++;
    volatile int x;
    asm (
        "LZCNT %1, %0"
    : "=r" (x)
    : "r" (n));

    return x;
}
