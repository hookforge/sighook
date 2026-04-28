#include <stdio.h>

#if defined(__aarch64__) && defined(__APPLE__)
long read_marker(void);

__asm__(
    ".text\n"
    ".globl _read_marker\n"
    ".globl _read_marker_patchpoint\n"
    "_read_marker:\n"
    "  mov x16, #0x1234\n"
    "_read_marker_patchpoint:\n"
    "  nop\n"
    "  mov x0, x16\n"
    "  ret\n");
#elif defined(__aarch64__) && defined(__linux__)
long read_marker(void);

__asm__(
    ".text\n"
    ".global read_marker\n"
    ".global read_marker_patchpoint\n"
    ".type read_marker, %function\n"
    "read_marker:\n"
    "  mov x16, #0x1234\n"
    "read_marker_patchpoint:\n"
    "  nop\n"
    "  mov x0, x16\n"
    "  ret\n"
    ".size read_marker, .-read_marker\n");
#else
__attribute__((noinline))
long read_marker(void) {
    return 0x1234;
}
#endif

int main(void) {
    printf("read_marker() = %ld\n", read_marker());
    return 0;
}
