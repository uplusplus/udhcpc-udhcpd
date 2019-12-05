/*
 *  FIPS-46-3 compliant 3DES implementation
 *
 *  Copyright (C) 2001-2003  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "stb_3des.h"
#include "string.h"
#include "stdio.h"
#include "strings.h"
/* the eight DES S-boxes */

uint32 SB1[64] =
{
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400,
    0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004,
    0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004,
    0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404,
    0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static uint32 SB2[64] =
{
    0x80108020, 0x80008000, 0x00008000, 0x00108020,
    0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000,
    0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000,
    0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020,
    0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020,
    0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static uint32 SB3[64] =
{
    0x00000208, 0x08020200, 0x00000000, 0x08020008,
    0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200,
    0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208,
    0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200,
    0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208,
    0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static uint32 SB4[64] =
{
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080,
    0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001,
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000,
    0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static uint32 SB5[64] =
{
    0x00000100, 0x02080100, 0x02080000, 0x42000100,
    0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000,
    0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000,
    0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100,
    0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100,
    0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static uint32 SB6[64] =
{
    0x20000010, 0x20400000, 0x00004000, 0x20404010,
    0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000,
    0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000,
    0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010,
    0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010,
    0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static uint32 SB7[64] =
{
    0x00200000, 0x04200002, 0x04000802, 0x00000000,
    0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002,
    0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800,
    0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802,
    0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802,
    0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000,
    0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000,
    0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800,
    0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static uint32 SB8[64] =
{
    0x10001040, 0x00001000, 0x00040000, 0x10041040,
    0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000,
    0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040,
    0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040,
    0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000,
    0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000,
    0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040,
    0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040,
    0x00001040, 0x00040040, 0x10000000, 0x10041000
};

/* PC1: left and right halves bit-swap */

static uint32 LHs[16] =
{
    0x00000000, 0x00000001, 0x00000100, 0x00000101,
    0x00010000, 0x00010001, 0x00010100, 0x00010101,
    0x01000000, 0x01000001, 0x01000100, 0x01000101,
    0x01010000, 0x01010001, 0x01010100, 0x01010101
};

static uint32 RHs[16] =
{
    0x00000000, 0x01000000, 0x00010000, 0x01010000,
    0x00000100, 0x01000100, 0x00010100, 0x01010100,
    0x00000001, 0x01000001, 0x00010001, 0x01010001,
    0x00000101, 0x01000101, 0x00010101, 0x01010101,
};

/* platform-independant 32-bit integer manipulation macros */

#define GET_UINT32(n,b,i)                       \
{                                               \
    (n) = ( (uint32) (b)[(i)    ] << 24 )       \
        | ( (uint32) (b)[(i) + 1] << 16 )       \
        | ( (uint32) (b)[(i) + 2] <<  8 )       \
        | ( (uint32) (b)[(i) + 3]       );      \
}

#define PUT_UINT32(n,b,i)                       \
{                                               \
    (b)[(i)    ] = (uint8) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8) ( (n)       );       \
}

/* Initial Permutation macro */

#define DES_IP(X,Y)                                             \
{                                                               \
    T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
    T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
    T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
    T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
    Y = ((Y << 1) | (Y >> 31)) & 0xFFFFFFFF;                    \
    T = (X ^ Y) & 0xAAAAAAAA; Y ^= T; X ^= T;                   \
    X = ((X << 1) | (X >> 31)) & 0xFFFFFFFF;                    \
}

/* Final Permutation macro */

#define DES_FP(X,Y)                                             \
{                                                               \
    X = ((X << 31) | (X >> 1)) & 0xFFFFFFFF;                    \
    T = (X ^ Y) & 0xAAAAAAAA; X ^= T; Y ^= T;                   \
    Y = ((Y << 31) | (Y >> 1)) & 0xFFFFFFFF;                    \
    T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
    T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
    T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
    T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
}

/* DES round macro */

#define DES_ROUND(X,Y)                          \
{                                               \
    T = *SK++ ^ X;                              \
    Y ^= SB8[ (T      ) & 0x3F ] ^              \
         SB6[ (T >>  8) & 0x3F ] ^              \
         SB4[ (T >> 16) & 0x3F ] ^              \
         SB2[ (T >> 24) & 0x3F ];               \
                                                \
    T = *SK++ ^ ((X << 28) | (X >> 4));         \
    Y ^= SB7[ (T      ) & 0x3F ] ^              \
         SB5[ (T >>  8) & 0x3F ] ^              \
         SB3[ (T >> 16) & 0x3F ] ^              \
         SB1[ (T >> 24) & 0x3F ];               \
}

/* DES key schedule */

static int des_main_ks( uint32 SK[32], uint8 key[8] )
{
    int i;
    uint32 X, Y, T;

    GET_UINT32( X, key, 0 );
    GET_UINT32( Y, key, 4 );

    /* Permuted Choice 1 */

    T =  ((Y >>  4) ^ X) & 0x0F0F0F0F;  X ^= T; Y ^= (T <<  4);
    T =  ((Y      ) ^ X) & 0x10101010;  X ^= T; Y ^= (T      );

    X =   (LHs[ (X      ) & 0xF] << 3) | (LHs[ (X >>  8) & 0xF ] << 2)
        | (LHs[ (X >> 16) & 0xF] << 1) | (LHs[ (X >> 24) & 0xF ]     )
        | (LHs[ (X >>  5) & 0xF] << 7) | (LHs[ (X >> 13) & 0xF ] << 6)
        | (LHs[ (X >> 21) & 0xF] << 5) | (LHs[ (X >> 29) & 0xF ] << 4);

    Y =   (RHs[ (Y >>  1) & 0xF] << 3) | (RHs[ (Y >>  9) & 0xF ] << 2)
        | (RHs[ (Y >> 17) & 0xF] << 1) | (RHs[ (Y >> 25) & 0xF ]     )
        | (RHs[ (Y >>  4) & 0xF] << 7) | (RHs[ (Y >> 12) & 0xF ] << 6)
        | (RHs[ (Y >> 20) & 0xF] << 5) | (RHs[ (Y >> 28) & 0xF ] << 4);

    X &= 0x0FFFFFFF;
    Y &= 0x0FFFFFFF;

    /* calculate subkeys */

    for( i = 0; i < 16; i++ )
    {
        if( i < 2 || i == 8 || i == 15 )
        {
            X = ((X <<  1) | (X >> 27)) & 0x0FFFFFFF;
            Y = ((Y <<  1) | (Y >> 27)) & 0x0FFFFFFF;
        }
        else
        {
            X = ((X <<  2) | (X >> 26)) & 0x0FFFFFFF;
            Y = ((Y <<  2) | (Y >> 26)) & 0x0FFFFFFF;
        }

        *SK++ =   ((X <<  4) & 0x24000000) | ((X << 28) & 0x10000000)
                | ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000)
                | ((X <<  6) & 0x01000000) | ((X <<  9) & 0x00200000)
                | ((X >>  1) & 0x00100000) | ((X << 10) & 0x00040000)
                | ((X <<  2) & 0x00020000) | ((X >> 10) & 0x00010000)
                | ((Y >> 13) & 0x00002000) | ((Y >>  4) & 0x00001000)
                | ((Y <<  6) & 0x00000800) | ((Y >>  1) & 0x00000400)
                | ((Y >> 14) & 0x00000200) | ((Y      ) & 0x00000100)
                | ((Y >>  5) & 0x00000020) | ((Y >> 10) & 0x00000010)
                | ((Y >>  3) & 0x00000008) | ((Y >> 18) & 0x00000004)
                | ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);

        *SK++ =   ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000)
                | ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000)
                | ((X >>  2) & 0x02000000) | ((X <<  1) & 0x01000000)
                | ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000)
                | ((X <<  3) & 0x00080000) | ((X >>  6) & 0x00040000)
                | ((X << 15) & 0x00020000) | ((X >>  4) & 0x00010000)
                | ((Y >>  2) & 0x00002000) | ((Y <<  8) & 0x00001000)
                | ((Y >> 14) & 0x00000808) | ((Y >>  9) & 0x00000400)
                | ((Y      ) & 0x00000200) | ((Y <<  7) & 0x00000100)
                | ((Y >>  7) & 0x00000020) | ((Y >>  3) & 0x00000011)
                | ((Y <<  2) & 0x00000004) | ((Y >> 21) & 0x00000002);
    }

    return( 0 );
}
#if 0
int des_set_key( des_context *ctx, uint8 *key )
{
    int i;

    /* setup encryption subkeys */

    des_main_ks( ctx->esk, key );

    /* setup decryption subkeys */

    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i    ] = ctx->esk[30 - i];
        ctx->dsk[i + 1] = ctx->esk[31 - i];
    }

    return( 0 );
}
#endif
/* DES 64-bit block encryption/decryption */

static void des_crypt( uint32 SK[32], uint8 input[8], uint8 output[8] )
{
    uint32 X, Y, T;

    GET_UINT32( X, input, 0 );
    GET_UINT32( Y, input, 4 );

    DES_IP( X, Y );

    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );

    DES_FP( Y, X );

    PUT_UINT32( Y, output, 0 );
    PUT_UINT32( X, output, 4 );
}

#if 0
static void des_encrypt( des_context *ctx, uint8 *input, uint8 *output ,int len)
{
    while( len > 0 )
    {
        
        
        des_crypt( ctx->esk, input, output );

        input  += 8;
        output += 8;
        len    -= 8;
    }

}

static void des_decrypt( des_context *ctx, uint8 *input, uint8 *output ,int len)
{
    while( len > 0 )
    {
        
        des_crypt( ctx->dsk, input, output );
        input  += 8;
        output += 8;
        len    -= 8;
    }


    
}
#endif
/* Triple-DES key schedule */

int des3_set_2keys( des3_context *ctx, uint8 *key)
{
    int i;

    des_main_ks( ctx->esk     , key);
    des_main_ks( ctx->dsk + 32, key+8);

    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i     ] = ctx->esk[30 - i];
        ctx->dsk[i +  1] = ctx->esk[31 - i];

        ctx->esk[i + 32] = ctx->dsk[62 - i];
        ctx->esk[i + 33] = ctx->dsk[63 - i];

        ctx->esk[i + 64] = ctx->esk[     i];
        ctx->esk[i + 65] = ctx->esk[ 1 + i];

        ctx->dsk[i + 64] = ctx->dsk[     i];
        ctx->dsk[i + 65] = ctx->dsk[ 1 + i];
    }

    return( 0 );
}

int des3_set_3keys( des3_context *ctx, uint8 *key)
{
    int i;

    des_main_ks( ctx->esk     , key );
    des_main_ks( ctx->dsk + 32, key+8);
    des_main_ks( ctx->esk + 64, key+16);

    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i     ] = ctx->esk[94 - i];
        ctx->dsk[i +  1] = ctx->esk[95 - i];

        ctx->esk[i + 32] = ctx->dsk[62 - i];
        ctx->esk[i + 33] = ctx->dsk[63 - i];

        ctx->dsk[i + 64] = ctx->esk[30 - i];
        ctx->dsk[i + 65] = ctx->esk[31 - i];
    }

    return( 0 );
}
/*
void des_cbc_encrypt( des_context *ctx,
                      unsigned char iv[8],
                      unsigned char *input,
                      unsigned char *output,
                      int len )
*/
void des_cbc_encrypt( des_context *ctx,
                      uint8 iv[8],
                      uint8 *input,
                      uint8 *output,
                      int len )

{
    int i;
    while( len > 0 )
    {
        
        for( i = 0; i < 8; i++ )
            output[i] = input[i] ^ iv[i];
        
        des_crypt( ctx->esk, output, output );
        memcpy( iv, output, 8 );

        input  += 8;
        output += 8;
        len    -= 8;
    }
}

/*
 * DES-CBC buffer decryption
 */
/*
void des_cbc_decrypt( des_context *ctx,
                      unsigned char iv[8],
                      unsigned char *input,
                      unsigned char *output,
                      int len )
*/
void des_cbc_decrypt( des_context *ctx,
                      uint8 iv[8],
                      uint8 *input,
                      uint8 *output,
                      int len )

{
    int i;
    unsigned char temp[8];

    while( len > 0 )
    {
        
        memcpy( temp, input, 8 );
        
        des_crypt( ctx->dsk, input, output );

        for( i = 0; i < 8; i++ )
            output[i] = output[i] ^ iv[i];

        memcpy( iv, temp, 8 );

        input  += 8;
        output += 8;
        len    -= 8;
    }
}




/* Triple-DES 64-bit block encryption/decryption */

static void des3_crypt( uint32 SK[96], uint8 input[8], uint8 output[8])
{
    uint32 X, Y, T;

    GET_UINT32( X, input, 0 );
    GET_UINT32( Y, input, 4 );

    DES_IP( X, Y );

    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );

    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );

    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );

    DES_FP( Y, X );

    PUT_UINT32( Y, output, 0 );
    PUT_UINT32( X, output, 4 );
}

void des3_encrypt( des3_context *ctx, uint8 *input, uint8 *output,int len )
{
    while(len >0)
    {

        des3_crypt( ctx->esk, input, output );

        input  += 8;
        output += 8;
        len    -= 8;

    }
}


void des3_decrypt( des3_context *ctx, uint8 *input, uint8 *output,int len )
{
    while(len >0)
    {
        des3_crypt( ctx->dsk, input, output );

        input  += 8;
        output += 8;
        len    -= 8;

    }
}

/*
 * 3DES-CBC buffer encryption
 */
/*
void des3_cbc_encrypt( des3_context *ctx,
                       unsigned char iv[8],
                       unsigned char *input,
                       unsigned char *output,
                       int len )
*/
void des3_cbc_encrypt( des3_context *ctx,
                      uint8 iv[8],
                      uint8 *input,
                      uint8 *output,
                      int len )

{
    int i;

    while( len > 0 )
    {
        for( i = 0; i < 8; i++ )
            output[i] = input[i] ^ iv[i];

        des3_crypt( ctx->esk, output, output );
        memcpy( iv, output, 8 );

        input  += 8;
        output += 8;
        len    -= 8;
    }
}

/*
 * 3DES-CBC buffer decryption
 */
/*
void des3_cbc_decrypt( des3_context *ctx,
                       unsigned char iv[8],
                       unsigned char *input,
                       unsigned char *output,
                       int len )
*/
void des3_cbc_decrypt( des3_context *ctx,
                      uint8 iv[8],
                      uint8 *input,
                      uint8 *output,
                      int len )

{
    int i;
    unsigned char temp[8];

    while( len > 0 )
    {
        memcpy( temp, input, 8 );
        des3_crypt( ctx->dsk, input, output );

        for( i = 0; i < 8; i++ )
            output[i] = output[i] ^ iv[i];

        memcpy( iv, temp, 8 );

        input  += 8;
        output += 8;
        len    -= 8;
    }
}
/*
int do_des(unsigned char *message,unsigned char *key,unsigned char *mode,unsigned char *iv)
{
    if((message == NULL) || (key == NULL) || (mode == NULL))
    {
        PDEBUG(2,"EInvalue input\n");
        return -1;
    }
    if(!strncasecmp(mode,"3ecb",4))
    {
        if(iv==NULL)
        {
            PDEBUG(2,"EInvalue input ,mode need IV\n");
            return -1;
        }
    }

}
*/



//#define TEST
#ifdef TEST

#include <string.h>
#include <stdio.h>

/*
 * Triple-DES Monte Carlo Test: ECB mode
 * source: NIST - tripledes-vectors.zip
 */
/*
static unsigned char DES3_keys[3][8] =
{
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
    { 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01 },
    { 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23 }
};

static unsigned char DES3_init[8] =
{
    0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74
};

static unsigned char DES3_enc_test[3][8] =
{
    { 0x6A, 0x2A, 0x19, 0xF4, 0x1E, 0xCA, 0x85, 0x4B },
    { 0x03, 0xE6, 0x9F, 0x5B, 0xFA, 0x58, 0xEB, 0x42 },
    { 0xDD, 0x17, 0xE8, 0xB8, 0xB4, 0x37, 0xD2, 0x32 }
};
    
static unsigned char DES3_dec_test[3][8] =
{
    { 0xCD, 0xD6, 0x4F, 0x2F, 0x94, 0x27, 0xC1, 0x5D },
    { 0x69, 0x96, 0xC8, 0xFA, 0x47, 0xA2, 0xAB, 0xEB },
    { 0x83, 0x25, 0x39, 0x76, 0x44, 0x09, 0x1A, 0x0A }
};
*/

int main(int argc,char **argv)
{
    int  i;
    int this_len = 16;
    des_context ctx;
    des3_context ctx3;
    unsigned char key[24];
    unsigned char out_buff[1024];
    unsigned char in_buff[1024];
    unsigned char buf[8];
    unsigned char temp_buff[8];

    unsigned char b_in_buff[1024];
    unsigned char b_out_buff[1024];
    bzero(b_out_buff,24);
    bzero(key,24);
    bzero(in_buff,24);
    bzero(out_buff,24);
    memcpy(in_buff,"12345678",8); //encrypt string
    memset(in_buff+8,0x8,8);
    memcpy(key,"000000000000000000000000",24); //encrypt key;
    bzero(b_in_buff,24);
    
    des_set_key(&ctx,key);
                    des_encrypt(&ctx,in_buff,out_buff,this_len);
                    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x ",out_buff[i]);
    printf("\n");
    #endif
    bzero(in_buff,24);
    des_decrypt( &ctx, out_buff, in_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x ",in_buff[i]);
#endif

      memcpy(buf,"12345678",8);//init IV
     memcpy(temp_buff,"12345678",8); //init IV
     #ifdef DEBUG
    printf("\n");
  
    printf("\n###################des_ecb######################\n");
#endif
    des_set_key(&ctx,key);
    memcpy(in_buff,"12345678",8); //encrypt string
    memset(in_buff+8,0x8,8);

    des_encrypt(&ctx,in_buff,out_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x:",out_buff[i]);
    printf("\n");
    #endif
    des_decrypt(&ctx,out_buff,b_in_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x:",b_in_buff[i]);
    
    printf("\n###################des_cbc######################\n");
#endif
    des_set_key(&ctx,key);
     memcpy(in_buff,"12345678",8); //encrypt string
    memset(in_buff+8,0x8,8);


    des_cbc_encrypt(&ctx,buf,in_buff,out_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x:",out_buff[i]);
    printf("\n");
    #endif
    des_cbc_decrypt(&ctx,temp_buff,out_buff,b_in_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x:",b_in_buff[i]);


    printf("\n");

    printf("\n###################3de-ecb######################\n");
#endif
    des3_set_3keys(&ctx3,key);
    memcpy(in_buff,"12345678",8); //encrypt string
    memset(in_buff+8,0x8,8);


    des3_encrypt(&ctx3,in_buff,out_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x:",out_buff[i]);
    printf("\n");
    #endif
    des3_decrypt(&ctx3,out_buff,b_in_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x:",b_in_buff[i]);
    printf("\n###################3des-cbc#####################\n");
#endif
    des3_set_3keys(&ctx3,key);
    
    des3_cbc_encrypt(&ctx3,buf,in_buff,out_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x:",out_buff[i]);
    printf("\n");
    #endif
    des3_cbc_decrypt(&ctx3,temp_buff,out_buff,in_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x:",in_buff[i]);



    printf("\n###################3de-ecb## test ####################\n");
#endif
    memcpy(key, "ad123456789111110000000000", 24);    //append '0' if key lengh is not enough

    des3_set_3keys(&ctx3,key);
    //memcpy(in_buff,"17750$AB458979013EF22231C4670E2BDD0580A5D7D66E$ad123456789$1110010012340010000000188BDB217C$192.168.222.201$00:09:6B:2D:FB:EB$$CTC",130); //encrypt string
	memcpy(in_buff,"1234567890123456",16);
	memset(in_buff+16,0x8,8);	// 136 = 17 * 8
	this_len = 24;

    des3_encrypt(&ctx3,in_buff,out_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02X",out_buff[i]);
                    //printf("%02x:",out_buff[i]);
    printf("\n");
    #endif
    des3_decrypt(&ctx3,out_buff,b_in_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%c",b_in_buff[i]);
                    //printf("%02x:",b_in_buff[i]);
    printf("\n###################3des-cbc###### test ###############\n");
#endif
    des3_set_3keys(&ctx3,key);
    
    des3_cbc_encrypt(&ctx3,buf,in_buff,out_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%02x",out_buff[i]);
    printf("\n");
    #endif
    des3_cbc_decrypt(&ctx3,temp_buff,out_buff,in_buff,this_len);
    #ifdef DEBUG
    for(i=0;i<this_len;i++)
                    printf("%c",in_buff[i]);

#endif
    /*
    for( m = 0; m < 2; m++ )
    {
        printf( "\n Tziriple-DES Monte Carlo Test (ECB mode) - " );

        if( m == 0 ) printf( "encryption\n\n" );
        if( m == 1 ) printf( "decryption\n\n" );

        for( n = 0; n < 3; n++ )
        {
            printf( " Test %d, key size = %3d bits: ",
                    n + 1, 64 + n * 64 );

            fflush( stdout );

           // memcpy( buf, DES3_init, 8 );
            

            switch( n )
            {
                case 0:
                    des_set_key( &ctx, DES3_keys[0] );
                    break;

                case 1:
                    des3_set_2keys( &ctx3, DES3_keys[0],
                                           DES3_keys[1] );
                    break;

                case 2:
                    des3_set_3keys( &ctx3, DES3_keys[0],
                                           DES3_keys[1],
                                           DES3_keys[2] );
                    des3_encrypt( &ctx3, buf, buf );
                    printf("buf=%s\n",buf);
                    break;
            }


            for( i = 0; i < 10000; i++ )
            {
                if( n == 0 )
                {
                    if( m == 0 ) des_encrypt( &ctx, buf, buf );
                    if( m == 1 ) des_decrypt( &ctx, buf, buf );
                }
                else
                {
                    if( m == 0 ) des3_encrypt( &ctx3, buf, buf );
                    if( m == 1 ) des3_decrypt( &ctx3, buf, buf );
                }
            }

            if( ( m == 0 && memcmp( buf, DES3_enc_test[n], 8 ) ) ||
                ( m == 1 && memcmp( buf, DES3_dec_test[n], 8 ) ) )
            {
                printf( "failed!\n" );
                return( 1 );
            }

            printf( "passed.\n" );
        }
    }
*/
#ifdef DEBUG
    printf( "\n" );
#endif
    return( 0 );
}

#endif
int HS_3des_encrypt(char okey[24],const unsigned char* in_buff,unsigned char* out_buff)
{
	des3_context ctx3;
	unsigned int len,m,i;
	char key[24];	
	char inBuf[128]={0};

	len = strlen((char *)in_buff);
	m = 8 - len % 8;
	strncpy(inBuf,in_buff,len);
	memset(inBuf+len,m,m);	// 136 = 17 * 8       
        des3_set_3keys(&ctx3,(uint8*)okey);	
	len += m;
        des3_encrypt(&ctx3,(uint8*)inBuf,(uint8*)out_buff,len);
        
	return len;					
}
