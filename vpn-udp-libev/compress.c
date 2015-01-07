#include "compress.h"

long tmp[LZO1_MEM_COMPRESS];
lzo_uint lzor;

int compress(unsigned char *in, unsigned char *out, int inlen)
{
    lzo1_compress(in, inlen, out, &lzor, tmp);
    return lzor;
}

int decompress(unsigned char *in, unsigned char *out, int inlen)
{
    lzo1_decompress(in, inlen, out, &lzor, NULL);
    return lzor;
}
