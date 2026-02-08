#include <stdio.h>

#if defined(__linux__) && defined(__aarch64__)
int calc(int a, int b);

__asm__(
    ".text\n"
    ".global calc\n"
    ".global calc_add_insn\n"
    ".type calc, %function\n"
    "calc:\n"
    "  mov x8, x0\n"
    "  mov x9, x1\n"
    "  nop\n"
    "  nop\n"
    "  nop\n"
    "calc_add_insn:\n"
    "  add w0, w8, w9\n"
    "  ret\n"
    ".size calc, .-calc\n");
#elif defined(__x86_64__) && defined(__APPLE__)
int calc(int a, int b);

__asm__(
    ".text\n"
    ".globl _calc\n"
    "_calc:\n"
    "  mov %edi, %eax\n"
    "  add %esi, %eax\n"
    "  nop\n"
    "  ret\n");
#elif defined(__x86_64__) && defined(__linux__)
int calc(int a, int b);

__asm__(
    ".text\n"
    ".global calc\n"
    ".type calc, @function\n"
    "calc:\n"
    "  mov %edi, %eax\n"
    "  add %esi, %eax\n"
    "  nop\n"
    "  ret\n"
    ".size calc, .-calc\n");
#elif defined(__aarch64__)
__attribute__((naked, noinline))
int calc(int a, int b) {
    __asm__ volatile(
        "mov x8, x0\n"
        "mov x9, x1\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "add w0, w8, w9\n"
        "ret\n");
}
#else
__attribute__((noinline))
int calc(int a, int b) {
    return a + b;
}
#endif

int main(void) {
    printf("calc(4, 5) = %d\n", calc(4, 5));
    return 0;
}
