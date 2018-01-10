#pragma once

#include <stdint.h>

#define MSR_IA32_EFER 0xc0000080

static inline void outb(uint16_t port, uint8_t val)
{
	asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port)
{
	uint8_t ret;
	asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
	return ret;
}

static inline uint64_t read_cr3(void)
{
	uint64_t ret;
	asm volatile("mov %%cr3, %0" : "=r"(ret));
	return ret;
}

static inline void write_cr3(uint64_t val)
{
	asm volatile("mov %0, %%cr3" : : "r"(val));
}

static inline void invlpg(void *addr)
{
	asm volatile("invlpg (%0)" : : "r"(addr) : "memory");
}

static inline void wrmsr(uint32_t msr_id, uint64_t val)
{
	uint64_t lo = val & 0xffffffff;
	uint64_t hi = val >> 32;
	asm volatile("wrmsr" : : "c"(msr_id), "a"(lo), "d"(hi));
}

static inline uint64_t rdmsr(uint32_t msr_id)
{
	uint64_t lo;
	uint64_t hi;
	asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr_id));
	return lo | (hi << 32);
}