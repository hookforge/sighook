#include <stdio.h>

__attribute__((noinline))
int target_add(int a, int b) {
    return a + b;
}

int main(void) {
    printf("target_add(6, 7) = %d\n", target_add(6, 7));
    return 0;
}
