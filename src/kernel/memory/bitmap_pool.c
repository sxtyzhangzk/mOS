#include <memory/bitmap_pool.h>
#include <arch/common/fault.h>
#include <stdint.h>

typedef uintptr_t bitmap_element;

static const size_t bitPerElement = sizeof(bitmap_element) * 8;

typedef struct bitmap_pool
{
	size_t			size;
	size_t			maxsize;
	bitmap_element	bitmap[0];
} bitmap_pool;

inline size_t bitmap_size(void *poolStart, void *poolEnd)
{
	return ((((char *)poolEnd - (char *)poolStart) - sizeof(bitmap_pool)) / sizeof(bitmap_element)) * bitPerElement;
}

void bitmap_pool_init(void *poolStart, void *poolEnd)
{
	bitmap_pool *pool = (bitmap_pool *)poolStart;
	pool->size = 0;
	pool->maxsize = bitmap_size(poolStart, poolEnd);

	size_t i;
	for (i = 0; i < pool->maxsize / bitPerElement; i++)
		pool->bitmap[i] = 0;
}

size_t bitmap_pool_allocate(void *poolStart)
{
	bitmap_pool *pool = (bitmap_pool *)poolStart;
	size_t i;
	for (i = 0; i < (pool->size + bitPerElement - 1) / bitPerElement; i++)
	{
		if (pool->bitmap[i] != ~0)
		{
			size_t bit;
			for (bit = 0; bit < bitPerElement && i * bitPerElement + bit < pool->size; bit++)
				if (!(pool->bitmap[i] & ((bitmap_element)1 << bit)))
					return i * bitPerElement + bit;
			return ~0;
		}
	}
	return ~0;
}

void bitmap_pool_free(void *poolStart, size_t idx)
{
	bitmap_pool *pool = (bitmap_pool *)poolStart;

	kassert(idx < pool->size);

	size_t i = idx / bitPerElement;
	size_t bit = idx % bitPerElement;

	kassert(pool->bitmap[i] & ((bitmap_element)1 << bit));

	pool->bitmap[idx / bitPerElement] &= ~((bitmap_element)1 << bit);
}

size_t bitmap_pool_push_back(void *poolStart, size_t delta)
{
	bitmap_pool *pool = (bitmap_pool *)poolStart;

	if (pool->size + delta <= pool->maxsize)
	{
		pool->size += delta;
		return pool->size;
	}

	return ~0;
}

void bitmap_pool_expand(void *poolStart, void *poolNewEnd)
{
	bitmap_pool *pool = (bitmap_pool *)poolStart;

	size_t newsize = bitmap_size(poolStart, poolNewEnd);

	kassert(newsize >= pool->maxsize);

	size_t i;
	for (i = pool->maxsize / bitPerElement; i < newsize / bitPerElement; i++)
		pool->bitmap[i] = 0;

	pool->maxsize = newsize;
}