#include <stdio.h>

#if defined(__aarch64__) && defined(__APPLE__)
int calc_prepatched(void);

__asm__(
    ".text\n"
    ".globl _calc_prepatched\n"
    ".globl _calc_prepatched_patchpoint\n"
    "_calc_prepatched:\n"
    "  mov x8, #40\n"
    "  mov x9, #2\n"
    "_calc_prepatched_patchpoint:\n"
    "  brk #0\n"
    "  ret\n");
#elif defined(__aarch64__) && defined(__linux__)
int calc_prepatched(void);

__asm__(
    ".text\n"
    ".global calc_prepatched\n"
    ".global calc_prepatched_patchpoint\n"
    ".type calc_prepatched, %function\n"
    "calc_prepatched:\n"
    "  mov x8, #40\n"
    "  mov x9, #2\n"
    "calc_prepatched_patchpoint:\n"
    "  brk #0\n"
    "  ret\n"
    ".size calc_prepatched, .-calc_prepatched\n");
#else
__attribute__((noinline))
int calc_prepatched(void) {
    return 42;
}
#endif

int main(void) {
    printf("calc_prepatched() = %d\n", calc_prepatched());
    return 0;
}
