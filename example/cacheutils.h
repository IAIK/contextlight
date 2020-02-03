#ifndef _CACHEUTILS_H_
#define _CACHEUTILS_H_

#if defined(__i386__) || defined(__x86_64__)
// ---------------------------------------------------------------------------
uint64_t rdtsc() {
  uint64_t a, d;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

// ---------------------------------------------------------------------------
void flush(void *p) { asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax"); }

// ---------------------------------------------------------------------------
void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }

// ---------------------------------------------------------------------------
void mfence() { asm volatile("mfence"); }
#elif defined(__aarch64__)
// ---------------------------------------------------------------------------
uint64_t rdtsc() {
#if 1
  struct timespec t1;
  clock_gettime(CLOCK_MONOTONIC, &t1);
  return t1.tv_sec * 1000 * 1000 * 1000ULL + t1.tv_nsec;
#else
  uint64_t result = 0;

  asm volatile("DSB SY");
  asm volatile("ISB");
  asm volatile("MRS %0, PMCCNTR_EL0" : "=r"(result));
  asm volatile("DSB SY");
  asm volatile("ISB");

  return result;
#endif
}

// ---------------------------------------------------------------------------
void flush(void *p) {
  asm volatile("DC CIVAC, %0" ::"r"(p));
  asm volatile("DSB ISH");
  asm volatile("ISB");
}

// ---------------------------------------------------------------------------
void maccess(void *p) {
  volatile uint32_t value;
  asm volatile("LDR %0, [%1]\n\t" : "=r"(value) : "r"(p));
  asm volatile("DSB ISH");
}

// ---------------------------------------------------------------------------
void mfence() { asm volatile("DSB ISH"); }
#endif

// ---------------------------------------------------------------------------
int flush_reload(void *ptr) {
  uint64_t start = 0, end = 0;

  start = rdtsc();
  maccess(ptr);
  end = rdtsc();

  flush(ptr);

  if (end - start < CACHE_MISS) {
    return 1;
  }
  return 0;
}

#endif
