//#define OVERWRITE_MALLOC

#ifndef _NOSPEC_H_
#define _NOSPEC_H_

#include <stdint.h>
#include <stdlib.h>


#ifdef NOSPEC_DISABLE
#define free_nospec free
#define malloc_nospec malloc
#define calloc_nospec calloc
#define realloc_nospec realloc
#define recalloc_nospec recalloc
#define reallocarray_nospec reallocarray
#define recallocarray_nospec recallocarray
#define nospec
#else
#define nospec __attribute__((section(".secret")))
void* malloc_nospec(size_t len);
void* secure_malloc(size_t len);
void free_nospec(void* addr);
void* calloc_nospec(size_t nmemb, size_t size);
void* reallocarray_nospec(void* addr, size_t nmemb, size_t size);
void* recallocarray_nospec(void* addr, size_t onmemb, size_t nmemb, size_t size);
void* realloc_nospec(void* addr, size_t size);
void* recalloc_nospec(void* addr, size_t size);
void nospec_set(void* addr, size_t len);

#ifdef OVERWRITE_MALLOC
#define malloc malloc_nospec
#define free free_nospec
#define calloc calloc_nospec
#define realloc realloc_nospec
#define recalloc recalloc_nospec
#endif //OVERWRITE_MALLOC
#endif
void nospec_secure_heap(int secure);

#endif
