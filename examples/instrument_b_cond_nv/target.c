#include <stdio.h>

#if defined(__aarch64__) && defined(__APPLE__)
int branch_nv(void);

__asm__(
    ".text\n"
    ".globl _branch_nv\n"
    ".globl _branch_nv_patchpoint\n"
    "_branch_nv:\n"
    "  mov w0, #1\n"
    "_branch_nv_patchpoint:\n"
    "  b.nv Lobserve_nv_taken\n"
    "  ret\n"
    "Lobserve_nv_taken:\n"
    "  mov w0, #2\n"
    "  ret\n");
#elif defined(__aarch64__) && defined(__linux__)
int branch_nv(void);

__asm__(
    ".text\n"
    ".global branch_nv\n"
    ".global branch_nv_patchpoint\n"
    ".type branch_nv, %function\n"
    "branch_nv:\n"
    "  mov w0, #1\n"
    "branch_nv_patchpoint:\n"
    "  b.nv .Lbranch_nv_taken\n"
    "  ret\n"
    ".Lbranch_nv_taken:\n"
    "  mov w0, #2\n"
    "  ret\n"
    ".size branch_nv, .-branch_nv\n");
#else
__attribute__((noinline))
int branch_nv(void) {
    return 2;
}
#endif

int main(void) {
    printf("branch_nv() = %d\n", branch_nv());
    return 0;
}
