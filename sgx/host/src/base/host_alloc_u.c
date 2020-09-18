#include <stdlib.h>
#include <stdio.h>

void ocall_host_alloc(void **out, size_t s)
{
	*out = malloc(s);
}

void host_free(void *in)
{
	free(in);
}

#define ENABLE_PRINT_STDOUT
#ifdef ENABLE_PRINT_STDOUT
void ocall_stdout(const char* format_str, const char *str)
{
	printf(format_str,str);
	fflush(stdout);
}
#endif
