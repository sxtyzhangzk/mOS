#include <efi.h>
#include <efilib.h>

#include <elf.h>
#include <arch/x86_64/bootloader.h>

static const EFI_MEMORY_TYPE EfiCustomType_Kernel = -1;

void *memcpy(void *dst, const void *src, size_t count)
{
	void *ret = dst;
	while(count--)
	{
		*((char *)dst) = *((char *)src);
		dst = (char *)dst + 1;
		src = (char *)src + 1;
	}
	return ret;
}

void enablePaging(void *pageTable)
{
	//asm(".intel_syntax noprefix");
	asm volatile("movq %0, %%cr3" : : "r" (pageTable) : );
}


EFI_STATUS loadFile(EFI_FILE_HANDLE fileRoot, CHAR16 *path, UINTN *sizeFile, void **buffer)
{
	EFI_STATUS ret;
	*buffer = NULL;

	EFI_FILE_HANDLE file = NULL;
	ret = uefi_call_wrapper(fileRoot->Open, 5, fileRoot, &file, path, EFI_FILE_MODE_READ, 0);

	if (ret != EFI_SUCCESS)
		return ret;

	UINTN sizeFileInfo = 0;
	EFI_FILE_INFO *fileInfo = NULL;
	ret = uefi_call_wrapper(file->GetInfo, 4, file, &GenericFileInfo, &sizeFileInfo, NULL);

	if (ret != EFI_SUCCESS && ret != EFI_BUFFER_TOO_SMALL)
		return ret;

	ret = uefi_call_wrapper(BS->AllocatePool, 3, EfiLoaderData, sizeFileInfo, &fileInfo);

	if (ret != EFI_SUCCESS)
		return ret;

	ret = uefi_call_wrapper(file->GetInfo, 4, file, &GenericFileInfo, &sizeFileInfo, (void *)fileInfo);

	if (ret != EFI_SUCCESS)
		return ret;

	*sizeFile = fileInfo->FileSize;
	ret = uefi_call_wrapper(BS->AllocatePool, 3, EfiLoaderData, *sizeFile, buffer);
	
	if (ret != EFI_SUCCESS)
		return ret;

	ret = uefi_call_wrapper(file->Read, 3, file, sizeFile, *buffer);

	if (ret != EFI_SUCCESS)
		return ret;

	uefi_call_wrapper(BS->FreePool, 1, (void *)fileInfo);

	uefi_call_wrapper(file->Close, 1, file);

	return EFI_SUCCESS;
}

EFI_STATUS loadKernelImage(UINTN sizeFile, UINT8 *buffer, void **pEntry, UINTN *nRegions, init_mem_region **pRegions)
{
	EFI_STATUS ret;

	if (sizeFile < sizeof(Elf64_Ehdr) ||
		buffer[0] != 0x7f ||
		buffer[1] != 'E' ||
		buffer[2] != 'L' ||
		buffer[3] != 'F')
	{
		return EFI_INVALID_PARAMETER;		// Not a ELF File
	}

	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buffer;

	if (ehdr->e_ident[EI_CLASS] != 2 || ehdr->e_ident[EI_DATA] != 1)
		return EFI_INVALID_PARAMETER;		// Not ELF64 little-endian file

	UINTN nPhdr = ehdr->e_phnum;
	UINTN sizePhdr = ehdr->e_phentsize;

	if (ehdr->e_phoff + nPhdr * sizePhdr > sizeFile)
		return EFI_INVALID_PARAMETER;		// Corrupted Image: Incorrect Program Header Number

	init_mem_region *regions = NULL;
	ret = uefi_call_wrapper(BS->AllocatePool, 3, EfiLoaderData, nPhdr * sizeof(init_mem_region), (void **)&regions);

	if (ret != EFI_SUCCESS)
		return ret;
	
	for (UINTN i = 0; i < nPhdr; i++)
	{
		Elf64_Phdr *phdr = (Elf64_Phdr *)(buffer + ehdr->e_phoff + i * sizePhdr);

		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_offset + phdr->p_filesz > sizeFile)
			return EFI_INVALID_PARAMETER;

		Elf64_Addr vaddrStart = phdr->p_vaddr & ~0xfff;
		Elf64_Addr vaddrEnd = (phdr->p_vaddr + phdr->p_memsz + 0xfff) & ~0xfff;
		UINTN nPages = (vaddrEnd - vaddrStart) >> 12;
		
		UINT8 *memory = NULL;
		ret = uefi_call_wrapper(BS->AllocatePages, 4, AllocateAnyPages, EfiCustomType_Kernel, nPages, &memory);

		if (ret != EFI_SUCCESS)
			return ret;

		for (UINTN j = 0; j < nPages << 12; j++)
			memory[j] = 0;
		for (UINTN j = 0; j < phdr->p_filesz; j++)
			memory[phdr->p_vaddr - vaddrStart + j] = buffer[phdr->p_offset + j];

		regions[i].paddr = (void *)memory;
		regions[i].vaddr = (void *)vaddrStart;
		regions[i].size = vaddrEnd - vaddrStart;
		regions[i].type = KernelImage;
	}
	
	*pRegions = regions;
	*nRegions = nPhdr;
	*pEntry = (void *)ehdr->e_entry;

	return EFI_SUCCESS;
}

EFI_STATUS exitBootService(EFI_HANDLE ImageHandle, EFI_MEMORY_DESCRIPTOR **pMemMap, UINTN *sizeDescriptor, UINTN *nDescriptor)
{
	EFI_STATUS ret;

	for (int retry = 0; retry < 3; retry++)
	{
		UINTN sizeMMap = 0;
		UINTN mapKey;
		UINT32 verDescriptor;

		ret = uefi_call_wrapper(BS->GetMemoryMap, 5, &sizeMMap, NULL, &mapKey, sizeDescriptor, &verDescriptor);

		if (ret != EFI_SUCCESS && ret != EFI_BUFFER_TOO_SMALL)
			return ret;

		EFI_MEMORY_DESCRIPTOR *memMap = NULL;
		ret = uefi_call_wrapper(BS->AllocatePool, 3, EfiLoaderData, sizeMMap, (void **)&memMap);

		if (ret != EFI_SUCCESS)
			return ret;

		ret = uefi_call_wrapper(BS->GetMemoryMap, 5, &sizeMMap, memMap, &mapKey, sizeDescriptor, &verDescriptor);

		if (ret != EFI_SUCCESS)
			return ret;

		ret = uefi_call_wrapper(BS->ExitBootServices, 2, ImageHandle, mapKey);

		if (ret == EFI_SUCCESS)
		{
			*pMemMap = memMap;
			*nDescriptor = sizeMMap / *sizeDescriptor;
			return EFI_SUCCESS;
		}

		if (ret != EFI_INVALID_PARAMETER)
			return ret;

		uefi_call_wrapper(BS->FreePool, 1, memMap);
	}

	return EFI_INVALID_PARAMETER;
}

void mapMemory(UINT64 *pageTable, UINT64 **pageTableEnd, UINTN layer, void *virtAddr, void *phyAddr)
{
	UINTN shift = 12 + layer * 9;
	UINTN mask = ((UINTN)0x1ffU) << shift;

	UINTN index = ((UINTN)virtAddr & mask) >> shift;

	if (layer == 0)
	{
		pageTable[index] = (UINTN)phyAddr | 0x3;
		return;
	}

	if (!(pageTable[index] & 0x1))
	{
		UINT64 *newPageTable = *pageTableEnd;
		*pageTableEnd += 0x1000;
		for (UINTN i = 0; i <= 0x1ff; i++)
			newPageTable[i] = 0;
		pageTable[index] = (UINTN)newPageTable | 0x3;
	}
	mapMemory((UINT64 *)(pageTable[index] & 0xffffffffff000), pageTableEnd, layer - 1, virtAddr, phyAddr);
}

void * allocatePages(EFI_MEMORY_DESCRIPTOR *memMap, UINTN sizeMemDescriptor, UINTN nMemDescriptor, UINTN nPages)
{
	for (UINTN i = 0; i < nMemDescriptor; i++)
	{
		EFI_MEMORY_DESCRIPTOR *memEntry = (EFI_MEMORY_DESCRIPTOR *)(((UINT8 *)memMap) + i * sizeMemDescriptor);
		if (memEntry->Type == EfiConventionalMemory && memEntry->NumberOfPages >= nPages)
		{
			memEntry->NumberOfPages -= nPages;
			memEntry->PhysicalStart += nPages << 12;
			return (void *)memEntry->PhysicalStart;
		}
	}
	return NULL;
}

UINTN initMemory(EFI_MEMORY_DESCRIPTOR *memMap, UINTN sizeMemDescriptor, UINTN nMemDescriptor, init_mem_region *regions, UINTN nRegions)
{
	UINTN sizeInitParam = sizeof(init_param) + sizeof(init_mem_region) * (nMemDescriptor + nRegions + 2);
	UINTN nPageInitParam = (sizeInitParam + 0xfff - 1) >> 12;
	init_param *initParam = allocatePages(memMap, sizeMemDescriptor, nMemDescriptor, nPageInitParam);
	void *initStack = allocatePages(memMap, sizeMemDescriptor, nMemDescriptor, 1);

	if (!initParam || !initStack)
		return 1;

	initParam->nMemRegions = nRegions;
	memcpy(&initParam->memRegions, regions, sizeof(init_mem_region) * nRegions);

	init_mem_region tmp;
	tmp.size = nPageInitParam << 12;
	tmp.paddr = initParam;
	tmp.vaddr = pInitParam;
	tmp.type = KernelData;

	initParam->memRegions[initParam->nMemRegions++] = tmp;

	tmp.size = 1 << 12;
	tmp.paddr = initStack;
	tmp.vaddr = pInitStack;
	tmp.type = KernelData;

	initParam->memRegions[initParam->nMemRegions++] = tmp;

	UINTN maxNPages = 0;
	EFI_MEMORY_DESCRIPTOR *memPageTable;

	// Find the largest memory region to store the page table (as we don't know how many pages the page table need)
	//  the page table should be continual so that the OS can easily map PhyAddr (in the page table region) to VirtAddr 
	for (UINTN i = 0; i < nMemDescriptor; i++)
	{
		EFI_MEMORY_DESCRIPTOR *memEntry = (EFI_MEMORY_DESCRIPTOR *)(((UINT8 *)memMap) + i * sizeMemDescriptor);
		if (memEntry->Type == EfiConventionalMemory && memEntry->NumberOfPages > maxNPages)
		{
			maxNPages = memEntry->NumberOfPages;
			memPageTable = memEntry;
		}
	}

	UINT64 *pageTable  = (UINT64 *)memPageTable->PhysicalStart;
	UINT64 *pageTableEnd = (UINT64 *)((UINT8 *)pageTable + 0x1000);

	for (UINTN i = 0; i <= 0x1ff; i++)
		pageTable[i] = 0;

	// Map the used memory region to virtual address
	for (UINTN i = 0; i < initParam->nMemRegions; i++)
	{
		UINTN nPages = initParam->memRegions[i].size >> 12;
		for (UINTN j = 0; j < nPages; j++)
			mapMemory(pageTable, &pageTableEnd, 3, (void *)((UINTN)initParam->memRegions[i].vaddr + j * 0x1000), (void *)((UINTN)initParam->memRegions[i].paddr + j * 0x1000));
	}

	// Map loader memory to virtual address
	// When the OS boots, it should clean up all entries in the page table that is not in init_mem_region
	for (UINTN i = 0; i < nMemDescriptor; i++)
	{
		EFI_MEMORY_DESCRIPTOR *memEntry = (EFI_MEMORY_DESCRIPTOR *)(((UINT8 *)memMap) + i * sizeMemDescriptor);
		if (memEntry->Type == EfiLoaderCode || memEntry->Type == EfiLoaderData || memEntry->Type == EfiBootServicesData)	//current stack is on BS Data
		{
			for (UINTN j = 0; j < memEntry->NumberOfPages; j++)
				mapMemory(pageTable, &pageTableEnd, 3, (void *)(memEntry->PhysicalStart + j * 0x1000), (void *)(memEntry->PhysicalStart + j * 0x1000));
		}
	}

	// Map the page table to virtual address
	//  note that the `pageTableEnd' may increase during the iteration
	//
	// <del> we allocate 3 more pages for the page table to prevent the OS from a special case 
	//    that there's no free page table entries to allocate more page tables </del>
	// we allocate getNumberOfBackPages( number of pages that page table used ) pages for the OS to initialize its data structure
	for (UINTN offset = 0; offset < pageTableEnd - pageTable + 0x1000 * getNumberOfBackupPages(((UINTN)pageTableEnd - (UINTN)pageTable) >> 12); offset += 0x1000)
		mapMemory(pageTable, &pageTableEnd, 3, (void *)((UINTN)pPageTable + offset), (void *)((UINTN)pageTable + offset));

	UINTN pageTableNumOfPages = (((UINTN)pageTableEnd - (UINTN)pageTable) >> 12);
	size_t nBackupPages = getNumberOfBackupPages(pageTableNumOfPages);
	initParam->nPageTableNumOfPages = pageTableNumOfPages;
	initParam->nBackupPages = nBackupPages;
	initParam->pPageTablePAddr = (uintptr_t)pageTable;

	if (pageTableNumOfPages + nBackupPages > memPageTable->NumberOfPages)
	{
		// We used too much memory to store the page table
		return 2;
	}
	memPageTable->NumberOfPages -= pageTableNumOfPages;
	memPageTable->PhysicalStart += pageTableNumOfPages << 12;

	// Let the OS know which regions are free
	for (UINTN i = 0; i < nMemDescriptor; i++)
	{
		EFI_MEMORY_DESCRIPTOR *memEntry = (EFI_MEMORY_DESCRIPTOR *)(((UINT8 *)memMap) + i * sizeMemDescriptor);
		if ((memEntry->Type == EfiConventionalMemory ||
			memEntry->Type == EfiLoaderCode ||
			memEntry->Type == EfiLoaderData ||
			memEntry->Type == EfiBootServicesCode ||
			memEntry->Type == EfiBootServicesData)
			&& memEntry->NumberOfPages > 0)
		{
			tmp.size = memEntry->NumberOfPages << 12;
			tmp.paddr = (void *)memEntry->PhysicalStart;
			tmp.vaddr = 0;
			tmp.type = Avaliable;
			initParam->memRegions[initParam->nMemRegions++] = tmp;
		}
	}

	enablePaging(pageTable);

	return 0;
}


EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
	EFI_STATUS ret;
	InitializeLib(ImageHandle, SystemTable);

	EFI_LOADED_IMAGE *loadedImage = NULL;
	ret = uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle, &LoadedImageProtocol, (void **)&loadedImage);

	if (ret != EFI_SUCCESS)
		return ret;

	Print(L"Bootloader Image Loaded at %lx\n", loadedImage->ImageBase);

	/*volatile int wait = 1;
	while (wait)
		asm("pause");*/

	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *simpleFS = NULL;
	ret = uefi_call_wrapper(BS->HandleProtocol, 3, loadedImage->DeviceHandle, &FileSystemProtocol, (void **)&simpleFS);

	if (ret != EFI_SUCCESS)
	{
		Print(L"Failed to open File System Protocol: %lx\n", ret);
		return ret;
	}

	EFI_FILE_HANDLE fileRoot = NULL;
	ret = uefi_call_wrapper(simpleFS->OpenVolume, 2, simpleFS, &fileRoot);

	if (ret != EFI_SUCCESS)
	{
		Print(L"Failed to open volume: %lx\n", ret);
		return ret;
	}

	UINTN sizeKernel = 0;
	void *bufferKernel = NULL;
	ret = loadFile(fileRoot, L"\\mOS-kernel", &sizeKernel, &bufferKernel);

	if (ret != EFI_SUCCESS)
	{
		Print(L"Failed to load kernel file: %lx\n", ret);
		return ret;
	}

	UINTN nRegions = 0;
	init_mem_region *regions = NULL;
	void(*entry)() = NULL;
	ret = loadKernelImage(sizeKernel, bufferKernel, (void **)&entry, &nRegions, &regions);

	if (ret != EFI_SUCCESS)
	{
		Print(L"Failed to load kernel image: %lx\n", ret);
		return ret;
	}

	EFI_MEMORY_DESCRIPTOR *memMap = NULL;
	UINTN sizeDescriptor, nDescriptor;

	ret = exitBootService(ImageHandle, &memMap, &sizeDescriptor, &nDescriptor);

	if (ret != EFI_SUCCESS)
	{
		Print(L"Failed to exit boot service: %lx\n", ret);
		return ret;
	}

	if (initMemory(memMap, sizeDescriptor, nDescriptor, regions, nRegions) == 0)
	{
		entry();
	}

	asm("hlt");

	return EFI_SUCCESS;
}