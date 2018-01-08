#pragma once

#include <stddef.h>


void	bitmap_pool_init(void *poolStart, void *poolEnd);
size_t	bitmap_pool_allocate(void *poolStart);				// return the index of allocated object, return ~0 if failed
void	bitmap_pool_free(void *poolStart, size_t idx);
size_t  bitmap_pool_push_back(void *poolStart, size_t delta);	// return the new size of the pool, return ~0 if failed
void	bitmap_pool_expand(void *poolStart, void *poolNewEnd);