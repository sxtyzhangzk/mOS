#include <arch/x86_64/memory.h>
#include <arch/x86_64/bootloader.h>
#include <utils/avl.h>
#include <memory/bitmap_pool.h>
#include <memory/mem_area.h>

// pcidPool[0] is the current global address space
PCIDPool pcidPool[MAX_PCID];

PageTableInfo * const		pPTInfo		= 0xffffff3000000000;
AVLNode * const				pMapPT		= 0xffffff4000000000;		// map phy addr to virt addr
MemArea * const				pMArea		= 0xffffff5000000000;
AddressSpaceInfo * const	pASInfo		= 0xffffff6000000000;
void * const				pPoolPT		= 0xffffff7000000000;
void * const				pPoolMArea	= 0xffffff7100000000;
void * const				pPoolASInfo = 0xffffff7200000000;

void * pPageTableEnd;
PageTableInfo * pPTInfoEnd;
AVLNode * pMapPTEnd;
MemArea * pMAreaEnd;
AddressSpaceInfo * pASInfoEnd;
void * pPoolPTEnd;
void * pPoolMAreaEnd;
void * pPoolASInfoEnd;

void init_memory()
{
	size_t i;
	for (i = 1; i < MAX_PCID; i++)
	{
		pcidPool[i].next = i + 1;
		pcidPool[i].prev = i - 1;
	}
	pcidPool[MAX_PCID].next = 0;


}