#pragma once

#include <arch/common/memory.h>
#include <arch/x86_64/page.h>
#include <stddef.h>
#include <utils/avl.h>

#define MAX_PCID 4096
#define PAGE_SIZE 0x1000

#define GLOBAL_START	0xffffff0000000000
#define GLOBAL_END		0xffffffffffffffff

typedef uintptr_t paddr;

typedef struct PageTableInfo
{
	paddr	phyAddr;
	size_t	refCount;
	AVLNode nodeMap;
} PageTableInfo;

typedef struct AddressSpaceInfo
{
	size_t		idxRootPageTable;
	uint16_t	pcid;
} AddressSpaceInfo;

typedef struct PCIDPool
{
	AddressSpaceInfo	*addrSpace;
	uint16_t			 prev, next;
} PCIDPool;

