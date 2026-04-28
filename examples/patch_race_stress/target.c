#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define WORKER_THREADS 4
#define WORKER_ITERS 200000

__attribute__((noinline))
int stress_target(int value) {
    return value + 1;
}

static void* worker_main(void* arg) {
    intptr_t worker_id = (intptr_t)arg;
    for (int i = 0; i < WORKER_ITERS; ++i) {
        int value = stress_target((int)(worker_id + i));
        if (value != 99 && value != (int)(worker_id + i + 1)) {
            fprintf(stderr, "unexpected value: %d\n", value);
            _Exit(2);
        }
    }
    return NULL;
}

int main(void) {
    pthread_t threads[WORKER_THREADS];

    for (intptr_t i = 0; i < WORKER_THREADS; ++i) {
        if (pthread_create(&threads[i], NULL, worker_main, (void*)i) != 0) {
            perror("pthread_create");
            return 3;
        }
    }

    for (int i = 0; i < WORKER_THREADS; ++i) {
        pthread_join(threads[i], NULL);
    }

    printf("stress ok\n");
    return 0;
}
