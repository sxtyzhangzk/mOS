#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef uintptr_t addr_space_handle;

void init_memory();
bool mem_map(void *vaddrStart, uintptr_t size);		// return false if there's no enough memory
void mem_map_fixed(void *vaddrStart, uintptr_t size, uintptr_t paddrStart);
void mem_unmap(void *vaddrStart, uintptr_t size);