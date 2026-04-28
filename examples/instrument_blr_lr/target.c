#include <stdio.h>

#if defined(__aarch64__) && defined(__APPLE__)
unsigned long observe_lr(void);
unsigned long observe_lr_expected(void);

__asm__(
    ".text\n"
    ".globl _observe_lr\n"
    ".globl _observe_lr_expected\n"
    ".globl _observe_lr_patchpoint\n"
    "_observe_lr:\n"
    "  mov x14, x30\n"
    "  adr x15, Lobserve_lr_callee\n"
    "_observe_lr_patchpoint:\n"
    "  blr x15\n"
    "Lobserve_lr_after:\n"
    "  mov x30, x14\n"
    "  ret\n"
    "Lobserve_lr_callee:\n"
    "  mov x0, x30\n"
    "  ret\n"
    "_observe_lr_expected:\n"
    "  adr x0, Lobserve_lr_after\n"
    "  ret\n");
#elif defined(__aarch64__) && defined(__linux__)
unsigned long observe_lr(void);
unsigned long observe_lr_expected(void);

__asm__(
    ".text\n"
    ".global observe_lr\n"
    ".global observe_lr_expected\n"
    ".global observe_lr_patchpoint\n"
    ".type observe_lr, %function\n"
    ".type observe_lr_expected, %function\n"
    "observe_lr:\n"
    "  mov x14, x30\n"
    "  adr x15, .Lobserve_lr_callee\n"
    "observe_lr_patchpoint:\n"
    "  blr x15\n"
    ".Lobserve_lr_after:\n"
    "  mov x30, x14\n"
    "  ret\n"
    ".Lobserve_lr_callee:\n"
    "  mov x0, x30\n"
    "  ret\n"
    "observe_lr_expected:\n"
    "  adr x0, .Lobserve_lr_after\n"
    "  ret\n"
    ".size observe_lr, .-observe_lr\n"
    ".size observe_lr_expected, .-observe_lr_expected\n");
#else
__attribute__((noinline))
unsigned long observe_lr(void) {
    return 0;
}

__attribute__((noinline))
unsigned long observe_lr_expected(void) {
    return 0;
}
#endif

int main(void) {
    printf(
        "observe_lr() = 0x%lx expected = 0x%lx\n",
        observe_lr(),
        observe_lr_expected());
    return 0;
}
