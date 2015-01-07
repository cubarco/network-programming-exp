#ifndef COMPRESS_H
#define COMPRESS_H

#include <lzo/lzo1.h>

int compress(unsigned char *in, unsigned char *out, int inlen);
int decompress(unsigned char *in, unsigned char *out, int inlen);

#endif
