#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__aarch64__) && defined(__APPLE__)
int literal_fault_fn(void);
void literal_fault_patchpoint(void);
char literal_fault_data_page(void);

__asm__(
    ".text\n"
    ".p2align 12\n"
    ".globl _literal_fault_fn\n"
    ".globl _literal_fault_patchpoint\n"
    ".globl _literal_fault_data_page\n"
    "_literal_fault_fn:\n"
    "  b Lliteral_fault_entry\n"
    "  .space 4096 - 4\n"
    "Lliteral_fault_entry:\n"
    "_literal_fault_patchpoint:\n"
    "  ldr w0, Lliteral_fault_data\n"
    "  ret\n"
    ".p2align 12\n"
    "_literal_fault_data_page:\n"
    "Lliteral_fault_data:\n"
    "  .word 0x12345678\n"
    "  .space 4096 - 4\n");
#elif defined(__aarch64__) && defined(__linux__)
int literal_fault_fn(void);
void literal_fault_patchpoint(void);
char literal_fault_data_page(void);

__asm__(
    ".text\n"
    ".p2align 12\n"
    ".global literal_fault_fn\n"
    ".global literal_fault_patchpoint\n"
    ".global literal_fault_data_page\n"
    ".type literal_fault_fn, %function\n"
    "literal_fault_fn:\n"
    "  b .Lliteral_fault_entry\n"
    "  .space 4096 - 4\n"
    ".Lliteral_fault_entry:\n"
    "literal_fault_patchpoint:\n"
    "  ldr w0, .Lliteral_fault_data\n"
    "  ret\n"
    ".p2align 12\n"
    "literal_fault_data_page:\n"
    ".Lliteral_fault_data:\n"
    "  .word 0x12345678\n"
    "  .space 4096 - 4\n"
    ".size literal_fault_fn, .-literal_fault_fn\n");
#else
int literal_fault_fn(void) {
    return 0;
}
void literal_fault_patchpoint(void) {}
char literal_fault_data_page(void) {}
#endif

static void on_fault(int signum, siginfo_t *info, void *uctx) {
    (void)signum;
    (void)info;

    uintptr_t pc = 0;
#if defined(__aarch64__) && defined(__APPLE__)
    ucontext_t *uc = (ucontext_t *)uctx;
    pc = (uintptr_t)uc->uc_mcontext->__ss.__pc;
#elif defined(__aarch64__) && defined(__linux__)
    ucontext_t *uc = (ucontext_t *)uctx;
    pc = (uintptr_t)uc->uc_mcontext.pc;
#endif

    uintptr_t patchpoint = (uintptr_t)&literal_fault_patchpoint;
    dprintf(
        STDOUT_FILENO,
        "fault_pc=0x%lx patchpoint=0x%lx match=%d\n",
        (unsigned long)pc,
        (unsigned long)patchpoint,
        pc == patchpoint);
    _exit(pc == patchpoint ? 0 : 2);
}

int main(void) {
    struct sigaction act;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t data_page = ((uintptr_t)&literal_fault_data_page) & ~(page_size - 1);
    void (*install_literal_fault_hook)(void) = NULL;

    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = on_fault;
    sigemptyset(&act.sa_mask);
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);

    install_literal_fault_hook = dlsym(RTLD_DEFAULT, "install_literal_fault_hook");
    if (install_literal_fault_hook != NULL) {
        install_literal_fault_hook();
    }

    if (mprotect((void *)data_page, page_size, PROT_NONE) != 0) {
        perror("mprotect");
        return 3;
    }

    (void)literal_fault_fn();
    return 4;
}
