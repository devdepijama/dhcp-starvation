#ifndef H_MEMORY
#define H_MEMORY

void memory_init();
void * memory_alloc(unsigned int size, char *description);
void memory_free(void *ptr, char *description);

#endif