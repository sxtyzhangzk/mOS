#pragma once

#include <arch/common/fault.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint64_t pt_entry;
typedef pt_entry *page_table;

#define PT_PRESENT	((uint64_t)1 << 0)
#define PT_RW		((uint64_t)1 << 1)
#define PT_US		((uint64_t)1 << 2)
#define PT_PWT		((uint64_t)1 << 3)
#define PT_PCD		((uint64_t)1 << 4)
#define PT_ACCESS	((uint64_t)1 << 5)
#define PT_DIRTY	((uint64_t)1 << 6)
#define PT_PS		((uint64_t)1 << 7)
#define PT_GLOBAL	((uint64_t)1 << 8)
#define PT_XD		((uint64_t)1 << 63)

static inline void set_paddr(pt_entry *entry, uint64_t paddr)
{
	kassert(!(paddr & 0xfff));
	kassert(paddr >> 52 == 0);
	*entry &= ~((((uint64_t)1 << 52) - 1) & ~0xfff);
	*entry |= paddr;
}

static inline uint64_t get_paddr(pt_entry entry)
{
	return entry & ((((uint64_t)1 << 52) - 1) & ~0xfff);
}