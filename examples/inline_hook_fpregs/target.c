#include <stdint.h>
#include <stdio.h>

#if defined(__linux__) && defined(__x86_64__)
typedef int32_t vec_t __attribute__((vector_size(32)));
#else
typedef int32_t vec_t __attribute__((vector_size(16)));
#endif

__attribute__((noinline))
vec_t target_vec_add(vec_t a, vec_t b) {
    return a + b;
}

static void print_vec(vec_t value) {
#if defined(__linux__) && defined(__x86_64__)
    printf(
        "target_vec_add = [%d, %d, %d, %d, %d, %d, %d, %d]\n",
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
        value[6],
        value[7]);
#else
    printf(
        "target_vec_add = [%d, %d, %d, %d]\n",
        value[0],
        value[1],
        value[2],
        value[3]);
#endif
}

int main(void) {
#if defined(__linux__) && defined(__x86_64__)
    vec_t a = {1, 2, 3, 4, 5, 6, 7, 8};
    vec_t b = {10, 20, 30, 40, 50, 60, 70, 80};
#else
    vec_t a = {1, 2, 3, 4};
    vec_t b = {10, 20, 30, 40};
#endif

    print_vec(target_vec_add(a, b));
    return 0;
}
