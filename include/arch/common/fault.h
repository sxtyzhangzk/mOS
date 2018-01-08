#pragma once

#ifdef NDEBUG

#define kassert(expr) ((void) 0)

#else

void kpanic(unsigned int code, const char *msg);

#define __str(x) # x
#define __xstr(x) __str(x)
#define kassert(expr) ((expr) ? (void)0 : kpanic(0x1, "Assertion '" #expr "' failed, file " __xstr(__FILE__) ", line " __xstr(__LINE__)))

#endif