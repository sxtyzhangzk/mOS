#include <memory/mem_area.h>
#include <arch/common/fault.h>

static inline MemArea *allocate_mem_area(MemAreaManager *self, uintptr_t addr, size_t size)
{
	MemArea *ret = self->funcAllocate();
	ret->nodeAddr.key = addr;
	ret->nodeAddr.val = (uintptr_t)ret;
	ret->nodeAddr.lchild = ret->nodeAddr.rchild = NULL;
	ret->nodeSize.key = size;
	ret->nodeSize.val = (uintptr_t)ret;
	ret->nodeSize.lchild = ret->nodeSize.rchild = NULL;
	return ret;
}

void mem_area_init(MemAreaManager *self, MemArea *(*allocator)(), void(*allocFree)(MemArea *), uintptr_t startAddr, size_t sizeAll, bool useRefCount)
{
	self->sizeFree = 0;
	self->funcAllocate = allocator;
	self->funcFree = allocFree;
	self->rootAddr = NULL;
	self->rootSize = NULL;
	self->useRefCount = useRefCount;
	
	MemArea *root = allocate_mem_area(self, startAddr, sizeAll);
	root->nRef = 1;

	avl_insert(&root->nodeAddr, &self->rootAddr);
}

uintptr_t mem_area_allocate(MemAreaManager *self, uintptr_t size, uintptr_t *pSize, bool forceSize)
{
	if (size == 0)
	{
		*pSize = 0;
		return 0;
	}

	AVLNode *node = avl_lower_bound(size, self->rootSize);
	if (!node)
	{
		if (forceSize)
		{
			*pSize = 0;
			return 0;
		}
		node = avl_upper_bound(~0, self->rootSize);
		if (!node)
		{
			*pSize = 0;
			return 0;
		}
		*pSize = node->key;
	}
	else
		*pSize = size;

	MemArea *area = (MemArea *)node->val;

	kassert(area->nRef == 0);

	if (area->nodeSize.key == *pSize)
	{
		area->nRef++;
		avl_erase(&area->nodeSize, &self->rootSize);
		self->sizeFree -= *pSize;
		return area->nodeAddr.key;
	}
	else
	{
		kassert(area->nodeSize.key > *pSize);
		area->nRef++;
		avl_erase(&area->nodeSize, &self->rootSize);

		MemArea *nextArea = allocate_mem_area(self, area->nodeAddr.key + *pSize, area->nodeSize.key - *pSize);
		nextArea->nRef = 0;
		avl_insert(&nextArea->nodeSize, &self->rootSize);
		avl_insert(&nextArea->nodeAddr, &self->rootAddr);

		area->nodeSize.key = *pSize;
		self->sizeFree -= *pSize;
		return area->nodeAddr.key;
	}
}

void mem_area_allocate_fixed(MemAreaManager *self, uintptr_t addr, uintptr_t size)
{
	if (size == 0)
		return;

	AVLNode *node = avl_upper_bound(addr, self->rootAddr);
	kassert(node);
	MemArea *area = (MemArea *)node->val;
		
	if (area->nodeAddr.key < addr)
	{
		kassert(area->nodeAddr.key + area->nodeSize.key > addr);
		MemArea *nextArea = allocate_mem_area(self, addr, area->nodeAddr.key + area->nodeSize.key - addr);
		if (area->nRef == 0)
		{
			avl_erase(&area->nodeSize, &self->rootSize);
			area->nodeSize.key -= nextArea->nodeSize.key;
			avl_insert(&area->nodeSize, &self->rootSize);
		}
		else
			area->nodeSize.key -= nextArea->nodeSize.key;
		nextArea->nRef = area->nRef;
		avl_insert(&nextArea->nodeAddr, &self->rootAddr);
		area = nextArea;
	}
	else
	{
		if (area->nRef == 0)
			avl_erase(&area->nodeSize, &self->rootSize);
	}

	while(1)
	{
		// area should never be on the size tree

		kassert(area->nodeAddr.key == addr);
		if (area->nodeSize.key > size)
		{
			MemArea *nextArea = allocate_mem_area(self, addr + size, area->nodeSize.key - size);
			nextArea->nRef = area->nRef;
			avl_insert(&nextArea->nodeAddr, &self->rootAddr);
			if (nextArea->nRef == 0)
				avl_insert(&nextArea->nodeSize, &self->rootSize);
			area->nodeSize.key = size;
		}

		if (area->nRef == 0)
			self->sizeFree -= area->nodeSize.key;
		area->nRef = self->useRefCount ? area->nRef + 1 : 1;
		addr += area->nodeSize.key;
		size -= area->nodeSize.key;

		if (size == 0)
			break;

		node = avl_upper_bound(addr, self->rootAddr);
		kassert(node);
		area = (MemArea *)node->val;

		if (area->nRef == 0)
			avl_erase(&area->nodeSize, &self->rootSize);
	}
}

void mem_area_free(MemAreaManager *self, uintptr_t addr, uintptr_t size)
{
	if (size == 0)
		return;

	AVLNode *node = avl_upper_bound(addr, self->rootAddr);
	kassert(node);
	MemArea *area = (MemArea *)node->val;

	MemArea *lastArea = NULL;

	if (area->nodeAddr.key < addr)
	{
		kassert(area->nodeAddr.key + area->nodeSize.key > addr);
		if (area->nRef == 0)
		{
			if (addr + size <= area->nodeAddr.key + area->nodeSize.key)
				return;

			uintptr_t delta = area->nodeAddr.key + area->nodeSize.key - addr;
			addr += delta;
			size -= delta;

			lastArea = area;
			node = avl_upper_bound(addr, self->rootAddr);
			kassert(node);
			area = (MemArea *)node->val;
		}
		else
		{
			lastArea = area;

			uintptr_t sizeSplit = area->nodeAddr.key + area->nodeSize.key - addr;
			MemArea *nextArea = allocate_mem_area(self, addr, sizeSplit);
			area->nodeSize.key -= sizeSplit;

			nextArea->nRef = area->nRef;
			avl_insert(&nextArea->nodeAddr, &self->rootAddr);
			area = nextArea;
		}
	}
	else if(addr > 0)
	{
		node = avl_upper_bound(addr - 1, self->rootAddr);
		if (node)
			lastArea = (MemArea *)node->val;
	}

	if (lastArea && lastArea->nRef == 0)
		avl_erase(&lastArea->nodeSize, &self->rootSize);

	while (1)
	{
		// last area should never be on size tree

		kassert(area->nodeAddr.key == addr);
		if (area->nodeSize.key > size)
		{
			if (area->nRef == 0)
			{
				if (lastArea->nRef == 0)
				{
					// MERGE lastArea & area
					lastArea->nodeSize.key += area->nodeSize.key;
					avl_erase(&area->nodeSize, &self->rootSize);
					avl_erase(&area->nodeAddr, &self->rootAddr);
					avl_insert(&lastArea->nodeSize, &self->rootSize);
					self->funcFree(area);
				}
				return;
			}
			MemArea *nextArea = allocate_mem_area(self, addr + size, area->nodeSize.key - size);
			nextArea->nRef = area->nRef;
			avl_insert(&nextArea->nodeAddr, &self->rootAddr);
			area->nodeSize.key = size;
		}

		if (area->nRef > 0)
		{
			area->nRef--;
			if (area->nRef == 0)
				self->sizeFree += area->nodeSize.key;
		}
		else
			avl_erase(&area->nodeSize, &self->rootSize);

		addr += area->nodeSize.key;
		size -= area->nodeSize.key;

		if (lastArea && area->nRef == lastArea->nRef)
		{
			// MERGE lastArea & area
			lastArea->nodeSize.key += area->nodeSize.key;
			avl_erase(&area->nodeAddr, &self->rootAddr);
			self->funcFree(area);
		}
		else
		{
			if (lastArea && lastArea->nRef == 0)
				avl_insert(&lastArea->nodeSize, &self->rootSize);
			lastArea = area;
		}

		if (size == 0)
			break;

		node = avl_upper_bound(addr, self->rootAddr);
		kassert(node);
		area = (MemArea *)node->val;
	}

	kassert(lastArea);

	node = avl_lower_bound(addr, self->rootAddr);
	if (node)
	{
		MemArea *nextArea = (MemArea *)node->val;
		if (nextArea->nRef == lastArea->nRef)
		{
			// MERGE lastArea & nextArea
			if (nextArea->nRef == 0)
				avl_erase(&nextArea->nodeSize, &self->rootSize);
			lastArea->nodeSize.key += nextArea->nodeSize.key;
			avl_erase(&nextArea->nodeAddr, &self->rootAddr);
			self->funcFree(nextArea);
		}
	}

	if (lastArea->nRef == 0)
		avl_insert(&lastArea->nodeSize, &self->rootSize);
}