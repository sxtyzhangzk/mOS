#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef uintptr_t addr_space_handle;
typedef uint32_t map_flag;

#define MAP_FLAG_READ		0x1
#define MAP_FLAG_WRITE		0x2
#define MAP_FLAG_EXECUTE	0x4

void init_memory(void);
bool mem_map(void *vaddrStart, uintptr_t size, map_flag flag);		// return false if there's no enough memory
void mem_map_fixed(void *vaddrStart, uintptr_t size, uintptr_t paddrStart, map_flag flag);
void mem_unmap(void *vaddrStart, uintptr_t size);
addr_space_handle fork_addr_space(void);
addr_space_handle current_addr_space(void);
void select_addr_space(addr_space_handle handle);
void delete_addr_space(addr_space_handle handle);