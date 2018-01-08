#include <arch/common/fault.h>

void kpanic(unsigned int code, const char *msg)
{
	asm("hlt");
}