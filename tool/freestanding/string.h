/* ALL A BOARD'S LIBC MUST GIVE THE SMALLEST HOST, sec 912: `make device-check`
 * compiles device/ against this and no other header, so an include of anything
 * more fails the build. Declarations only; a board has these from its own C
 * library or a few lines of its own. */
#ifndef FZN_FREESTANDING_STRING_H
#define FZN_FREESTANDING_STRING_H

#include <stddef.h>

void *memcpy(void *to, const void *from, size_t n);
void *memmove(void *to, const void *from, size_t n);
void *memset(void *to, int byte, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

#endif
