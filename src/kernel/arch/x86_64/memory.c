#include <arch/x86_64/memory.h>
#include <arch/x86_64/bootloader.h>
#include <utils/avl.h>
#include <memory/bitmap_pool.h>
#include <memory/mem_area.h>
#include <arch/x86_64/asm.h>

// pcidPool[0] is the current global address space
PCIDPool pcidPool[MAX_PCID];

PageTableInfo * const		pPTInfo		= 0xffffff4000000000;
MemArea * const				pMArea		= 0xffffff5000000000;
AddressSpaceInfo * const	pASInfo		= 0xffffff6000000000;
void * const				pPoolPT		= 0xffffff7000000000;
void * const				pPoolMArea	= 0xffffff7100000000;
void * const				pPoolASInfo = 0xffffff7200000000;

uintptr_t pPageTableEnd;
uintptr_t pPTInfoEnd;
uintptr_t pMAreaEnd;
uintptr_t pASInfoEnd;
uintptr_t pPoolPTEnd;
uintptr_t pPoolMAreaEnd;
uintptr_t pPoolASInfoEnd;

AVLNode *mapPTRoot;		// the root node of the map of (phy -> virt)

AddressSpaceInfo *globalAddrSpace;
AddressSpaceInfo *currentAddrSpace;
MemAreaManager paManager;

// Number of remained backup pages. Used during the initialization.
size_t nBackupPages;

static MemArea *alloc_mem_area_struct();
static void free_mem_area_struct(MemArea *area);
static void page_table_map(page_table pageTableRoot, uintptr_t vaddrStart, uintptr_t size, uintptr_t paddrStart, map_flag flag);
static void prealloc_resource(void);

static inline page_table current_root_pagetable(void)
{
	return (page_table)((uintptr_t)pPageTable + currentAddrSpace->idxRootPageTable * PAGE_SIZE);
}

static inline bool page_align(uintptr_t val)
{
	return val % PAGE_SIZE == 0;
}

// layer: 0 for PageTable, 3 for PML4
// map as Read/Write Supervisor page
static void page_table_map_init(pt_entry *pageTable, uint8_t layer, uintptr_t vaddr, uintptr_t paddr)
{
	uintptr_t index = (vaddr >> (12 + 9 * layer)) & 0x1ff;
	
	if (layer == 0)
	{
		kassert(!(pageTable[index] & PT_PRESENT));
		set_paddr(&pageTable[index], paddr);
		pageTable[index] |= PT_PRESENT | PT_RW | PT_XD;
		return;
	}

	if (!(pageTable[index] & PT_PRESENT))
	{
		kassert(nBackupPages);
		nBackupPages--;
		set_paddr(&pageTable[index], pInitParam->pPageTablePAddr + pPageTableEnd - (uintptr_t)pPageTable);
		pPageTableEnd += PAGE_SIZE;
		pageTable[index] |= PT_PRESENT;
	}

	page_table_map_init(get_paddr(pageTable[index]) - pInitParam->pPageTablePAddr + (uintptr_t)pPageTable, layer - 1, vaddr, paddr);
}

static uintptr_t find_free_page_init(void)
{
	size_t i;
	for (i = 0; i < pInitParam->nMemRegions; i++)
	{
		if (pInitParam->memRegions[i].type == Avaliable && pInitParam->memRegions[i].size > 0)
		{
			uintptr_t addr = pInitParam->memRegions[i].paddr;
			pInitParam->memRegions[i].paddr += PAGE_SIZE;
			pInitParam->memRegions[i].size -= PAGE_SIZE;
			return addr;
		}
	}
	kassert(false);
}

void init_memory(void)
{
	uint64_t msr_val = rdmsr(MSR_IA32_EFER);
	msr_val |= 1 << 11;	// NXE
	wrmsr(MSR_IA32_EFER, msr_val);

	size_t i;
	for (i = 1; i < MAX_PCID; i++)
	{
		pcidPool[i].next = i + 1;
		pcidPool[i].prev = i - 1;
	}
	pcidPool[MAX_PCID].next = 0;

	nBackupPages = pInitParam->nBackupPages;
	pPageTableEnd = (void *)((uintptr_t)pPageTable + PAGE_SIZE * pInitParam->nPageTableNumOfPages);

	// init addressspace pool
	page_table_map_init(pPageTable, 3, pPoolASInfo, find_free_page_init());
	pPoolASInfoEnd = pPoolASInfo + PAGE_SIZE;
	bitmap_pool_init(pPoolASInfo, pPoolASInfoEnd);

	// init addressspace array
	page_table_map_init(pPageTable, 3, pASInfo, find_free_page_init());
	pASInfoEnd = pASInfo + PAGE_SIZE;
	size_t nASInfo = ((uintptr_t)pASInfoEnd - (uintptr_t)pASInfo) / sizeof(AddressSpaceInfo);
	size_t ret = bitmap_pool_push_back(pPoolASInfo, nASInfo);
	kassert(ret != ~0);

	// init pagetable pool
	page_table_map_init(pPageTable, 3, pPoolPT, find_free_page_init());
	pPoolPTEnd = pPoolASInfo + PAGE_SIZE;
	bitmap_pool_init(pPoolPT, pPoolPTEnd);

	size_t nPTInfo = 0;
	pPTInfoEnd = pPTInfo;
	while (nPTInfo < pInitParam->nPageTableNumOfPages + pInitParam->nBackupPages)
	{
		page_table_map_init(pPageTable, 3, pPTInfoEnd, find_free_page_init());
		pPTInfoEnd += PAGE_SIZE;
		nPTInfo = (pPTInfoEnd - (uintptr_t)pPTInfo) / sizeof(PageTableInfo);
	}

	while (bitmap_pool_push_back(pPoolPT, pInitParam->nPageTableNumOfPages + pInitParam->nBackupPages) == ~0)
	{
		page_table_map_init(pPageTable, 3, pPoolPTEnd, find_free_page_init());
		pPoolPTEnd += PAGE_SIZE;
		bitmap_pool_expand(pPoolPT, pPoolPTEnd);
	}

	// init memarea pool
	page_table_map_init(pPageTable, 3, pPoolMArea, find_free_page_init());
	pPoolMAreaEnd = (uintptr_t)pPoolMArea + PAGE_SIZE;
	bitmap_pool_init(pPoolMArea, pPageTableEnd);

	// init memarea array
	page_table_map_init(pPageTable, 3, pMArea, find_free_page_init());
	pMAreaEnd = (uintptr_t)pMArea + PAGE_SIZE;
	ret = bitmap_pool_push_back(pPoolMArea, (pMAreaEnd - (uintptr_t)pMArea) / sizeof(MemArea));
	kassert(ret != ~0);

	for (i = 0; i < (pPageTableEnd - (uintptr_t)pPageTable) / PAGE_SIZE; i++)
	{
		bitmap_pool_set_in_use(pPoolPT, i);
		pPTInfo[i].refCount = 1;
	}

	pPageTableEnd += nBackupPages * PAGE_SIZE;
	nBackupPages = 0;

	mapPTRoot = NULL;

	for (i = 0; i < (pPageTableEnd - (uintptr_t)pPageTable) / PAGE_SIZE; i++)
	{
		pPTInfo[i].nodeMap.key = pPTInfo[i].phyAddr = pInitParam->pPageTablePAddr + i * PAGE_SIZE;
		pPTInfo[i].nodeMap.val = pPageTable + i * PAGE_SIZE;
		avl_insert(&pPTInfo[i].nodeMap, &mapPTRoot);
	}

	// we shouldn't use `page_table_map_init' from now on

	mem_area_init(&paManager, alloc_mem_area_struct, free_mem_area_struct, 0, (size_t)1 << (64 - 12), true);

	for (i = 0; i < pInitParam->nMemRegions; i++)
	{
		if (pInitParam->memRegions[i].type == Avaliable && pInitParam->memRegions[i].size > 0)
			mem_area_free(&paManager, pInitParam->memRegions[i].paddr, pInitParam->memRegions[i].size);
	}

	currentAddrSpace->idxRootPageTable = 0;
	currentAddrSpace->pcid = 0;

	globalAddrSpace = currentAddrSpace;
}


//////////////////////////////////////

static uintptr_t pFreeLastStart;
static uintptr_t pFreeLastSize;

static uintptr_t pAddRefLastStart;
static uintptr_t pAddRefLastSize;

static void phy_memory_flush(void)
{
	if (pFreeLastSize == 0 && pAddRefLastSize == 0)
		return;

	prealloc_resource();

	if (pAddRefLastSize != 0)
		mem_area_allocate_fixed(&paManager, pAddRefLastStart / PAGE_SIZE, pAddRefLastSize / PAGE_SIZE);
	if (pFreeLastSize != 0)
		mem_area_free(&paManager, pFreeLastStart / PAGE_SIZE, pFreeLastSize / PAGE_SIZE);

	pAddRefLastStart = 0;
	pAddRefLastSize = 0;
	pFreeLastStart = 0;
	pFreeLastSize = 0;
}

static void free_phy_memory(uintptr_t paddr, uintptr_t size)
{
	kassert(page_align(paddr));
	kassert(page_align(size));

	if (paddr == pFreeLastStart + pFreeLastSize)
		pFreeLastSize += size;
	else
	{
		phy_memory_flush();
		pFreeLastStart = paddr;
		pFreeLastSize = size;
	}
}

static void addref_phy_memory(uintptr_t paddr, uintptr_t size)
{
	kassert(page_align(paddr));
	kassert(page_align(size));

	if (paddr == pAddRefLastStart + pAddRefLastSize)
		pAddRefLastSize += size;
	else
	{
		phy_memory_flush();
		pAddRefLastStart = paddr;
		pAddRefLastSize = size;
	}
}

//////////////////////////////////////


static MemArea *alloc_mem_area_struct()
{
	size_t idx = bitmap_pool_allocate(pPoolMArea);
	kassert(idx != ~0);
	return &pMArea[idx];
}

static void free_mem_area_struct(MemArea *area)
{
	size_t idx = area - pMArea;
	bitmap_pool_free(pPoolMArea, idx);
}

static inline page_table paddr2vaddr(uintptr_t paddr)
{
	AVLNode *node = avl_find(paddr, mapPTRoot);
	kassert(node);
	return (page_table)node->val;
}

static inline size_t vaddr2idx(page_table pt)
{
	return ((uintptr_t)pt - (uintptr_t)pPageTable) / PAGE_SIZE;
}

static inline PageTableInfo * vaddr2pinfo(page_table pt)
{
	return &pPTInfo[vaddr2idx(pt)];
}

//return the vaddr of next level page table
static inline page_table alloc_page_table(pt_entry *entry)
{
	size_t idxPageTable = bitmap_pool_allocate(pPoolPT);
	kassert(idxPageTable != ~0);

	set_paddr(entry, pPTInfo[idxPageTable].phyAddr);
	*entry |= PT_PRESENT;

	kassert(pPTInfo[idxPageTable].refCount == 0);
	pPTInfo[idxPageTable].refCount = 1;

	return (pt_entry *)((uintptr_t)pPageTable + idxPageTable * PAGE_SIZE);
}

// push down the information contained by entry to next layer, return the pointer to next layer page table
static page_table pushdown_entry(pt_entry *entry, uint8_t layer)	
{
	kassert(layer > 0);

	size_t i;

	if (*entry & PT_PS)
	{
		pt_entry oldEntry = *entry;
		page_table pNextLevel = alloc_page_table(entry);
		for (i = 0; i < (1 << 9); i++)
		{
			pNextLevel[i] = oldEntry;
			if (layer - 1 == 0)
				pNextLevel[i] &= ~(PT_PS);
			set_paddr(&pNextLevel[i], get_paddr(oldEntry) + i * (1 << (12 + 9 * (layer - 1))));
		}
		return pNextLevel;
	}

	page_table pNextLevel = paddr2vaddr(get_paddr(*entry));
	PageTableInfo *info = vaddr2pinfo(pNextLevel);

	if (info->refCount > 1)
	{
		info->refCount--;
		page_table pNewNextLevel = alloc_page_table(entry);
		for (i = 0; i < (1 << 9); i++)
		{
			pNewNextLevel[i] = pNextLevel[i];
			if (!(pNewNextLevel[i] & PT_PRESENT))
				continue;
			if ((layer - 1 > 0) && !(pNewNextLevel[i] & PT_PS))
			{
				vaddr2pinfo(paddr2vaddr(get_paddr(pNewNextLevel[i])))->refCount++;
			}
			else
			{
				addref_phy_memory(get_paddr(pNewNextLevel[i]), 1 << (12 + 9 * (layer - 1)));
			}
		}
		return pNewNextLevel;
	}
	else
		return pNextLevel;
}

// make the `entry' a valid entry pointing to next level page table
static inline page_table prepare_page_table(pt_entry *entry, uint8_t layer)
{
	kassert(layer > 0);

	if (!(*entry & PT_PRESENT))
		return alloc_page_table(entry);
	return pushdown_entry(entry, layer);
}

static void inv_tlb(pt_entry *entry, uint8_t layer, uintptr_t layerStart)
{
	if (!(*entry & PT_PRESENT))
		return;
	if (layer == 0 || *entry & PT_PS)
		invlpg(layerStart);
	else
	{
		page_table nextlayer = paddr2vaddr(get_paddr(*entry));
		size_t i;
		for (i = 0; i < (1 << 9); i++)
			inv_tlb(&nextlayer[i], layer - 1, layerStart + (1 << (12 + 9 * (layer - 1))));
	}
}

// free all resource controlled by the page table entry `entry' (including physical memory, page table info)
static void free_entry(pt_entry *entry, uint8_t layer, uintptr_t layerStart)
{
	if (!(*entry & PT_PRESENT))
		return;
	if (layer == 0 || *entry & PT_PS)
	{
		free_phy_memory(get_paddr(*entry), 1 << (12 + 9 * layer));
		*entry = 0;
		invlpg(layerStart);
	}
	else
	{
		page_table nextlayer = paddr2vaddr(get_paddr(*entry));
		PageTableInfo *info = vaddr2pinfo(nextlayer);
		info->refCount--;
		if(info->refCount == 0)
		{
			size_t i;
			for (i = 0; i < (1 << 9); i++)
				free_entry(&nextlayer[i], layer - 1, layerStart + i * (1 << 12 + 9 * (layer - 1)));
			bitmap_pool_free(pPoolPT, vaddr2idx(nextlayer));
		}
		else
		{
			size_t i;
			for (i = 0; i < (1 << 9); i++)
				inv_tlb(&nextlayer[i], layer - 1, layerStart + i * (1 << 12 + 9 * (layer - 1)));
		}
	}
}

// [layerStart, layerEnd] the region that is controlled by this page table
static void page_table_map_impl(
	page_table pageTable, uint8_t layer, uintptr_t layerStart,
	uintptr_t vaddrStart, uintptr_t size, uintptr_t paddrStart,
	map_flag flag)
{
	const uintptr_t regionSizePerEntry = 1 << (12 + 9 * layer);
	const uintptr_t layerEnd = layerStart + (1 << 9) * regionSizePerEntry - 1;

	uintptr_t indexStart = vaddrStart >= layerStart ? (vaddrStart >> (12 + 9 * layer)) & 0x1ff : 0;
	uintptr_t indexEnd = vaddrStart + size - 1 <= layerEnd ? ((vaddrStart + size - 1) >> (12 + 9 * layer)) & 0x1ff : 0x1ff;

	size_t i;

	uintptr_t indexL, indexR;

	if (vaddrStart > layerStart + indexStart * regionSizePerEntry)
	{
		page_table vaddr = prepare_page_table(&pageTable[indexStart], layer);

		page_table_map_impl(vaddr, layer - 1,
			layerStart + indexStart * regionSizePerEntry,
			vaddrStart, size, paddrStart, flag);
		indexL = indexStart + 1;
	}
	else
		indexL = indexStart;

	if (indexEnd != indexStart && vaddrStart + size - 1 < layerStart + (indexEnd + 1) * regionSizePerEntry - 1)
	{
		page_table vaddr = prepare_page_table(&pageTable[indexEnd], layer);

		page_table_map_impl(vaddr, layer - 1,
			layerStart + indexEnd * regionSizePerEntry,
			vaddrStart, size, paddrStart, flag);
		indexR = indexEnd - 1;
	}
	else
		indexR = indexEnd;

	if (layer == 3)	// 512GB page size not supported by CPU
	{
		for (i = indexL; i <= indexR; i++)
		{
			page_table vaddr = prepare_page_table(&pageTable[i], layer);
			page_table_map_impl(vaddr, layer - 1,
				layerStart + i * regionSizePerEntry, vaddrStart, size, paddrStart, flag);
		}
	}
	else
	{
		for (i = indexL; i <= indexR; i++)
		{
			uintptr_t vaddr = layerStart + i * regionSizePerEntry;
			uintptr_t paddr = vaddr - vaddrStart + paddrStart;

			free_entry(&pageTable[i], layer, vaddr);

			pageTable[i] = 0;
			set_paddr(&pageTable[i], paddr);
			if (flag & MAP_FLAG_WRITE)
				pageTable[i] |= PT_RW;
			if (!(flag & MAP_FLAG_EXECUTE))
				pageTable[i] |= PT_XD;
			if (vaddr >= GLOBAL_START && vaddr <= GLOBAL_END)
				pageTable[i] |= PT_GLOBAL;
			if (layer != 0)
				pageTable[i] |= PT_PS;
			pageTable[i] |= PT_PRESENT;
		}
	}
}

static void page_table_unmap_impl(
	page_table pageTable, uint8_t layer, uintptr_t layerStart,
	uintptr_t vaddrStart, uintptr_t size)
{
	const uintptr_t regionSizePerEntry = 1 << (12 + 9 * layer);
	const uintptr_t layerEnd = layerStart + (1 << 9) * regionSizePerEntry - 1;

	uintptr_t indexStart = vaddrStart >= layerStart ? (vaddrStart >> (12 + 9 * layer)) & 0x1ff : 0;
	uintptr_t indexEnd = vaddrStart + size - 1 <= layerEnd ? ((vaddrStart + size - 1) >> (12 + 9 * layer)) & 0x1ff : 0x1ff;

	size_t i;

	uintptr_t indexL, indexR;

	if (vaddrStart > layerStart + indexStart * regionSizePerEntry)
	{
		if (pageTable[indexStart] & PT_PRESENT)
		{
			page_table_unmap_impl(paddr2vaddr(get_paddr(pageTable[indexStart])), layer - 1,
				layerStart + indexStart * regionSizePerEntry,
				vaddrStart, size);
		}
		indexL = indexStart + 1;
	}
	else
		indexL = indexStart;
	if (indexEnd != indexStart && vaddrStart + size - 1 < layerStart + (indexEnd + 1) * regionSizePerEntry - 1)
	{
		if (pageTable[indexEnd] & PT_PRESENT)
		{
			page_table_unmap_impl(paddr2vaddr(get_paddr(pageTable[indexEnd])), layer - 1,
				layerStart + indexEnd * regionSizePerEntry,
				vaddrStart, size);
		}
		indexR = indexEnd - 1;
	}
	else
		indexR = indexEnd;

	for (i = indexL; i <= indexR; i++)
		free_entry(&pageTable[i], layer, layerStart + i * regionSizePerEntry);
}

static void page_table_map(page_table pageTableRoot, uintptr_t vaddrStart, uintptr_t size, uintptr_t paddrStart, map_flag flag)
{
	kassert(!(vaddrStart & (PAGE_SIZE - 1)));
	kassert(!(paddrStart & (PAGE_SIZE - 1)));
	kassert(!(size & (PAGE_SIZE - 1)));
	kassert(size > 0);
	page_table_map_impl(pageTableRoot, 3, 0, vaddrStart, size, paddrStart & 0x0000ffffffffffffU, flag);
	phy_memory_flush();
}

static void page_table_unmap(page_table pageTableRoot, uintptr_t vaddrStart, uintptr_t size)
{
	kassert(page_align(vaddrStart));
	kassert(page_align(size));
	kassert(size > 0);
	page_table_unmap_impl(pageTableRoot, 3, 0, vaddrStart, size);
	phy_memory_flush();
}

static void sbrk_array(uintptr_t *pArrayEnd, size_t pageAlloc, map_flag flag)
{
	while (pageAlloc > 0)
	{
		size_t nPage;
		uintptr_t paddr = mem_area_allocate(&paManager, pageAlloc, &nPage, false) * PAGE_SIZE;
		page_table_map(current_root_pagetable(), *pArrayEnd, nPage * PAGE_SIZE, paddr, flag);
		*pArrayEnd += nPage * PAGE_SIZE;
		pageAlloc -= nPage;
	}
}

static void prealloc_resource(void)
{
	static bool reent = false;
	kassert(!reent);
	reent = true;

	enum Resource
	{
		PoolPT = 0,
		ArrayPageInfo = 1,
		PageTable = 2,
		PoolMA = 3,
		ArrayMemArea = 4,
		MAX_RESOURCE
	};
	intptr_t resRemain[MAX_RESOURCE];
	intptr_t resRequire[MAX_RESOURCE];
	size_t pageAlloc[MAX_RESOURCE] = { 0 };

	resRequire[PoolPT] = 0;
	resRequire[ArrayPageInfo] = 0;
	resRequire[PageTable] = 576;
	resRequire[PoolMA] = 0;
	resRequire[ArrayMemArea] = 7;

	resRemain[PoolPT] = bitmap_pool_get_maxsize(pPoolPT) - bitmap_pool_get_size(pPoolPT);
	resRemain[ArrayPageInfo] = (pPTInfoEnd - (uintptr_t)pPTInfo) / sizeof(PageTableInfo) - bitmap_pool_get_used(pPoolPT);
	resRemain[PageTable] = bitmap_pool_get_size(pPoolPT) - bitmap_pool_get_used(pPoolPT);
	resRemain[PoolMA] = bitmap_pool_get_maxsize(pPoolMArea) - bitmap_pool_get_size(pPoolMArea);
	resRemain[ArrayMemArea] = bitmap_pool_get_size(pPoolMArea) - bitmap_pool_get_used(pPoolMArea);

	while (1)
	{
		bool flag = false;
		if (resRemain[PoolPT] < resRequire[PoolPT])
		{
			if (pageAlloc[PoolPT] == 0)
			{
				resRemain[PageTable] -= 3;
				resRemain[ArrayMemArea] -= 1;
			}
			const size_t itemPerPage = PAGE_SIZE * 8;
			size_t nPage = (resRequire[PoolPT] - resRemain[PoolPT] + itemPerPage - 1) / itemPerPage;
			resRemain[PoolPT] += nPage * itemPerPage;
			pageAlloc[PoolPT] += nPage;
			flag = true;
		}
		if (resRemain[ArrayPageInfo] < resRequire[ArrayPageInfo])
		{
			if (pageAlloc[PoolPT] == 0)
			{
				resRemain[PageTable] -= 3;
				resRemain[ArrayMemArea] -= 1;
			}
			const size_t itemPerPage = PAGE_SIZE / sizeof(PageTableInfo);
			size_t nPage = (resRequire[ArrayPageInfo] - resRemain[ArrayPageInfo] + itemPerPage - 1) / itemPerPage;
			resRemain[ArrayPageInfo] += nPage * itemPerPage;
			pageAlloc[ArrayPageInfo] += nPage;
			flag = true;
		}
		if (resRemain[PageTable] < resRequire[PageTable])
		{
			if (pageAlloc[PoolPT] == 0)
			{
				resRemain[PageTable] -= 3;
				resRemain[ArrayMemArea] -= 1;
			}
			size_t nPage = resRequire[PageTable] - resRemain[PageTable];
			resRemain[PageTable] += nPage;
			resRemain[ArrayPageInfo] -= nPage;
			resRemain[PoolPT] -= nPage;
			pageAlloc[PageTable] += nPage;
			flag = true;
		}
		if (resRemain[PoolMA] < resRequire[PoolMA])
		{
			if (pageAlloc[PoolMA] == 0)
			{
				resRemain[PageTable] -= 3;
				resRemain[ArrayMemArea] -= 1;
			}
			const size_t itemPerPage = PAGE_SIZE * 8;
			size_t nPage = (resRequire[PoolMA] - resRemain[PoolMA] + itemPerPage - 1) / itemPerPage;
			resRemain[PoolMA] += nPage * itemPerPage;
			pageAlloc[PoolMA] += nPage;
			flag = true;
		}
		if (resRemain[ArrayMemArea] < resRequire[ArrayMemArea])
		{
			if (pageAlloc[ArrayMemArea] == 0)
			{
				resRemain[PageTable] -= 3;
				resRemain[ArrayMemArea] -= 1;
			}
			const size_t itemPerPage = PAGE_SIZE / sizeof(MemArea);
			size_t nPage = (resRequire[ArrayMemArea] - resRemain[ArrayMemArea] + itemPerPage - 1) / itemPerPage;
			resRemain[ArrayMemArea] += nPage * itemPerPage;
			resRemain[PoolMA] -= nPage * itemPerPage;
			pageAlloc[ArrayMemArea] += nPage;
			flag = true;
		}
		if (!flag)
			break;
	}

	if (pageAlloc[PoolPT])
	{
		sbrk_array(&pPoolPTEnd, pageAlloc[PoolPT], MAP_FLAG_READ | MAP_FLAG_WRITE);
		bitmap_pool_expand(pPoolPT, pPoolPTEnd);
	}
	if (pageAlloc[ArrayPageInfo])
		sbrk_array(&pPTInfoEnd, pageAlloc[ArrayPageInfo], MAP_FLAG_READ | MAP_FLAG_WRITE);
	if (pageAlloc[PageTable])
	{
		sbrk_array(&pPageTableEnd, pageAlloc[PageTable], MAP_FLAG_READ | MAP_FLAG_WRITE);
		size_t ret = bitmap_pool_resize(pPoolPT, (pPageTableEnd - (uintptr_t)pPageTable) / PAGE_SIZE);
		kassert(ret != ~0);
	}
	if (pageAlloc[PoolMA])
	{
		sbrk_array(&pPoolMAreaEnd, pageAlloc[PoolMA], MAP_FLAG_READ | MAP_FLAG_WRITE);
		bitmap_pool_expand(pPoolMArea, pPoolMAreaEnd);
	}
	if (pageAlloc[ArrayMemArea])
	{
		sbrk_array(&pMAreaEnd, pageAlloc[ArrayMemArea], MAP_FLAG_READ | MAP_FLAG_WRITE);
		size_t ret = bitmap_pool_resize(pPoolMArea, (pMAreaEnd - (uintptr_t)pMArea) / sizeof(MemArea));
		kassert(ret != ~0);
	}

	reent = false;
}

bool mem_map(void *vaddrStart, uintptr_t size, map_flag flag)
{
	kassert(!(size & (PAGE_SIZE - 1)));
	prealloc_resource();

	size_t nPage = size / PAGE_SIZE;
	if (paManager.sizeFree < nPage)
		return false;

	uintptr_t ptr = (uintptr_t)vaddrStart;
	sbrk_array(&ptr, nPage, flag);

	return true;
}

void mem_map_fixed(void *vaddrStart, uintptr_t size, uintptr_t paddrStart, map_flag flag)
{
	kassert(!(size & (PAGE_SIZE - 1)));
	kassert(!(paddrStart & (PAGE_SIZE - 1)));
	prealloc_resource();

	mem_area_allocate_fixed(&paManager, paddrStart / PAGE_SIZE, size / PAGE_SIZE);
	page_table_map(current_root_pagetable(), vaddrStart, size, paddrStart, flag);
}

void mem_unmap(void *vaddrStart, uintptr_t size)
{
	page_table_unmap(current_root_pagetable(), vaddrStart, size);
}

addr_space_handle fork_addr_space(void)
{
	size_t idx = bitmap_pool_allocate(pPoolASInfo);
	if (idx == ~0)
	{
		prealloc_resource();
		sbrk_array(pASInfoEnd, 1, MAP_FLAG_READ | MAP_FLAG_WRITE);
		size_t ret = bitmap_pool_resize(pPoolASInfo, (pASInfoEnd - (uintptr_t)pASInfo) / sizeof(AddressSpaceInfo));
		if (ret == ~0)
		{
			prealloc_resource();
			sbrk_array(pPoolASInfoEnd, 1, MAP_FLAG_READ | MAP_FLAG_WRITE);
			bitmap_pool_expand(pPoolASInfo, pPoolASInfoEnd);
			bitmap_pool_resize(pPoolASInfo, (pASInfoEnd - (uintptr_t)pASInfo) / sizeof(AddressSpaceInfo));
		}
		idx = bitmap_pool_allocate(pPoolASInfo);
		kassert(idx != ~0);
	}
	AddressSpaceInfo *asInfo = &pASInfo[idx];
	pt_entry entry = 0;
	page_table pt = alloc_page_table(&entry);
	asInfo->idxRootPageTable = vaddr2idx(pt);
	asInfo->pcid = 0;

	page_table ptCurrent = current_root_pagetable();

	size_t i = 0;
	for (i = 0; i < (1 << 9); i++)
	{
		pt[i] = ptCurrent[i];
		if (pt[i] & PT_PRESENT)
		{
			uintptr_t vaddr = i * (1 << (12 + 9 * 3));
			if (!(vaddr >= GLOBAL_START && vaddr <= GLOBAL_END))
				vaddr2pinfo(paddr2vaddr(get_paddr(pt[i])))->refCount++;
		}
	}

	return (addr_space_handle)asInfo;
}

addr_space_handle current_addr_space(void)
{
	return (addr_space_handle)currentAddrSpace;
}

void select_addr_space(addr_space_handle handle)
{
	AddressSpaceInfo *asInfo = (AddressSpaceInfo *)handle;
	kassert((uintptr_t)asInfo >= (uintptr_t)pASInfo && (uintptr_t)asInfo < pASInfoEnd);

	if (asInfo == globalAddrSpace)
	{
		uint64_t cr3 = 0;
		cr3 |= pPTInfo[asInfo->idxRootPageTable].phyAddr << 12;
		cr3 |= ((uint64_t)1 << 63);
		write_cr3(cr3);
		return;
	}

	bool newPCID = false;
	if (asInfo->pcid == 0)
	{
		newPCID = true;
		asInfo->pcid = pcidPool[0].prev;
		if(pcidPool[asInfo->pcid].addrSpace)
			pcidPool[asInfo->pcid].addrSpace->pcid = 0;
		pcidPool[asInfo->pcid].addrSpace = asInfo;
	}
	pcidPool[pcidPool[asInfo->pcid].prev].next = pcidPool[asInfo->pcid].next;
	pcidPool[pcidPool[asInfo->pcid].next].prev = pcidPool[asInfo->pcid].prev;
	pcidPool[pcidPool[0].next].prev = asInfo->pcid;
	pcidPool[asInfo->pcid].next = pcidPool[0].next;
	pcidPool[asInfo->pcid].prev = 0;
	pcidPool[0].next = asInfo->pcid;

	uint64_t cr3 = asInfo->pcid;
	cr3 |= pPTInfo[asInfo->idxRootPageTable].phyAddr << 12;
	if(!newPCID)
		cr3 |= ((uint64_t)1 << 63);
	write_cr3(cr3);

	currentAddrSpace = asInfo;
}

void delete_addr_space(addr_space_handle handle)
{
	AddressSpaceInfo *asInfo = (AddressSpaceInfo *)handle;
	kassert(asInfo != currentAddrSpace);

	page_table_unmap((uintptr_t)pPageTable + asInfo->idxRootPageTable * PAGE_SIZE, 0, GLOBAL_START);

	bitmap_pool_free(pPoolPT, asInfo->idxRootPageTable);

	if (asInfo->pcid != 0)
	{
		pcidPool[asInfo->pcid].addrSpace = NULL;
		asInfo->pcid = 0;
	}
	asInfo->idxRootPageTable = 0;

	bitmap_pool_free(pPoolASInfo, asInfo - pASInfo);
}