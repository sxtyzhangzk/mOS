#pragma once

#include <stddef.h>

typedef enum mem_region_type
{
	Avaliable,
	KernelImage,
	KernelData,
	Reserved
} mem_region_type;

typedef struct init_mem_region
{
	void			*vaddr;
	void			*paddr;
	size_t			 size;
	mem_region_type  type;
} init_mem_region;

typedef struct init_param
{
	size_t			nPageTableNumOfPages;
	size_t			nMemRegions;
	init_mem_region	memRegions[0];
} init_param;

static init_param * const pInitParam = (init_param *)0xffffffff00000000;
static void * const pInitStack = (void *)0xfffffffffffff000;
static void * const pPageTable = (void *)0xffffff0000000000;