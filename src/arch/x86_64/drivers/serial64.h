#ifndef SERIAL64_H
#define SERIAL64_H

#include "types.h"

void serial64_putc(char value);
void serial64_write(const char *text);
void serial64_hex(u64 value);
void serial64_dec(u64 value);

#endif
