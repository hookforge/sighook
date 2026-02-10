#include <stdio.h>

volatile int g_magic = 30;

#if defined(__linux__) && defined(__aarch64__)
int calc(int a, int b);

__asm__(
    ".text\n"
    ".global calc\n"
    ".global calc_adrp_insn\n"
    ".type calc, %function\n"
    "calc:\n"
    "  mov x8, x0\n"
    "  mov x9, x1\n"
    "calc_adrp_insn:\n"
    "  adrp x10, g_magic\n"
    "  add x10, x10, :lo12:g_magic\n"
    "  ldr w10, [x10]\n"
    "  add w0, w8, w9\n"
    "  add w0, w0, w10\n"
    "  ret\n"
    ".size calc, .-calc\n");
#else
__attribute__((noinline))
int calc(int a, int b) {
    return a + b + g_magic;
}
#endif

int main(void) {
    printf("calc(5, 7) = %d\n", calc(5, 7));
    return 0;
}
