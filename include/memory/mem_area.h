#pragma once

#include <utils/avl.h>
#include <stdbool.h>

typedef struct MemArea
{
	AVLNode	nodeSize;
	AVLNode	nodeAddr;
	size_t	nRef;
} MemArea;

typedef struct MemAreaManager
{
	AVLNode *rootSize;
	AVLNode *rootAddr;

	MemArea *(*funcAllocate)();
	void(*funcFree)(MemArea *);
	size_t sizeFree;
	bool useRefCount;
} MemAreaManager;

void mem_area_init(MemAreaManager *self, MemArea *(*allocator)(), void (*allocFree)(MemArea *), uintptr_t startAddr, size_t sizeAll, bool useRefCount);
uintptr_t mem_area_allocate(MemAreaManager *self, uintptr_t size, uintptr_t *pSize, bool forceSize);
void mem_area_allocate_fixed(MemAreaManager *self, uintptr_t addr, uintptr_t size);
void mem_area_free(MemAreaManager *self, uintptr_t addr, uintptr_t size);