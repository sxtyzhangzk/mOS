#pragma once

#include <arch/common/memory.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_PCID 4096
#define PAGE_TABLE_SIZE 0x1000

typedef uintptr_t paddr;
typedef uint64_t pt_entry;

typedef struct PageTableInfo
{
	paddr	phyAddr;
	size_t	refCount;
} PageTableInfo;

typedef struct AddressSpaceInfo
{
	size_t		idxRootPageTable;
	bool		isGlobal;
	uint16_t	pcid;
} AddressSpaceInfo;

typedef struct PCIDPool
{
	AddressSpaceInfo	*addrSpace;
	uint16_t			 prev, next;
} PCIDPool;

