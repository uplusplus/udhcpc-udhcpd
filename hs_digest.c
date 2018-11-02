/********************************************************************************** 
* @file hs_digest.c
* @brief summary for MD5 and SHA1 algorithm
* @version 1.0 2008.10
**********************************************************************************/
#include "hs_digest.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*****************************MD5***************************/
/*used in md5 STB_dep_MD5Transform*/
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21 

/* F, G, H and I are basic MD5 functions.*/
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* ROTATE_LEFT rotates x left n bits.*/
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n)))) 

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
  Rotation is separate from addition to prevent recomputation.*/
#define FF(a, b, c, d, x, s, ac) { \
  (a) += F ((b), (c), (d)) + (x) + (unsigned long)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define GG(a, b, c, d, x, s, ac) { \
  (a) += G ((b), (c), (d)) + (x) + (unsigned long)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define HH(a, b, c, d, x, s, ac) { \
  (a) += H ((b), (c), (d)) + (x) + (unsigned long)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 }
#define II(a, b, c, d, x, s, ac) { \
  (a) += I ((b), (c), (d)) + (x) + (unsigned long)(ac); \
  (a) = ROTATE_LEFT ((a), (s)); \
  (a) += (b); \
 } 
/***********************SHA1*****************************/
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif
//#define SHA1HANDSOFF 

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#ifdef LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#else
#define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);



static void STB_dep_MD5Encode(unsigned char *output, unsigned long *input,unsigned int  len)
{
	unsigned int i, j; 

	for(i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
} 

static void STB_dep_MD5Decode(unsigned long *output, unsigned char *input, unsigned int  len)
{
	unsigned int i, j; 

	for(i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((unsigned long)input[j]) | (((unsigned long)input[j+1]) << 8) |
		(((unsigned long)input[j+2]) << 16) | (((unsigned long)input[j+3]) << 24);
} 


static void STB_dep_MD5Transform (unsigned long state[4], unsigned char block[64])
{
	unsigned long a = state[0], b = state[1], c = state[2], d = state[3], x[16]; 

	STB_dep_MD5Decode(x, block, 64); 

	/* Round 1 */
	FF(a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF(b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */ 

	/* Round 2 */
	GG(a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */ 

	/* Round 3 */
	HH(a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH(a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */ 

	/* Round 4 */
	II(a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II(d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */ 

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d; 

	/* Zeroize sensitive information. */
	memset((unsigned char *)x, 0, sizeof(x));
}

void STB_dep_MD5Init (MD5_CTX *context)
{
	context->count[0] = context->count[1] = 0; 

	/* Load magic initialization constants.*/
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

void STB_dep_MD5Update(MD5_CTX *context, unsigned char * input, unsigned int  inputLen)
{
	unsigned int i, index, partLen; 

	index = (unsigned int)((context->count[0] >> 3) & 0x3F); 

	if((context->count[0] += ((unsigned long)inputLen << 3)) < ((unsigned long)inputLen << 3))
		context->count[1]++;
	context->count[1] += ((unsigned long)inputLen >> 29); 

	partLen = 64 - index; 

	if(inputLen >= partLen) 
	{
		memcpy((unsigned char *)&context->buffer[index], (unsigned char *)input, partLen);

		STB_dep_MD5Transform(context->state, context->buffer); 

		for(i = partLen; i + 63 < inputLen; i += 64)
			STB_dep_MD5Transform(context->state, &input[i]); 

		index = 0;
	}
	else
		i = 0; 

	memcpy((unsigned char *)&context->buffer[index], (unsigned char *)&input[i], inputLen-i);
} 

void STB_dep_MD5Final (unsigned char digest[16], MD5_CTX *context)
{
	unsigned char bits[8];
	unsigned char padding[64]={0};
	unsigned int index, padLen; 

	STB_dep_MD5Encode(bits, context->count, 8); 

	index = (unsigned int)((context->count[0] >> 3) & 0x3f);

	padLen = (index < 56) ? (56 - index) : (120 - index);

	padding[0] = 0x80;
	STB_dep_MD5Update(context, padding, padLen); 

	STB_dep_MD5Update(context, bits, 8); 

	STB_dep_MD5Encode(digest, context->state, 16); 

	/* Zeroize sensitive information. */ 
	memset((unsigned char *)context, 0, sizeof(*context));
} 

static void STB_dep_SHA1Transform(unsigned long state[5], unsigned char buffer[64])
{
	unsigned long a, b, c, d, e;
	typedef union {
		unsigned char c[64];
		unsigned long l[16];
	} CHAR64LONG16;
	CHAR64LONG16* block;
	#ifdef SHA1HANDSOFF
	static unsigned char workspace[64];
	block = (CHAR64LONG16*)workspace;
	memcpy(block, buffer, 64);
	#else
	block = (CHAR64LONG16*)buffer;
	#endif
	/* Copy context->state[] to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
	/* Add the working vars back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	/* Wipe variables */
	a = b = c = d = e = 0;
}

void STB_dep_SHA1Init(SHA1_CTX* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

void STB_dep_SHA1Update(SHA1_CTX* context, unsigned char* data, unsigned int len)
{
	unsigned int i, j;

	j = (context->count[0] >> 3) & 63;
	if ((context->count[0] += len << 3) < (len << 3)) 
		context->count[1]++;
	context->count[1] += (len >> 29);
	if ((j + len) > 63) {
		memcpy(&context->buffer[j], data, (i = 64-j));
		STB_dep_SHA1Transform(context->state, context->buffer);
		for ( ; i + 63 < len; i += 64) {
			STB_dep_SHA1Transform(context->state, &data[i]);
		}
		j = 0;
	}
	else i = 0;
	memcpy(&context->buffer[j], &data[i], len - i);
}

void STB_dep_SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
	unsigned long i, j;
	unsigned char finalcount[8];

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
		>> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
	}
	STB_dep_SHA1Update(context, (unsigned char *)"\200", 1);
	while ((context->count[0] & 504) != 448) {
		STB_dep_SHA1Update(context, (unsigned char *)"\0", 1);
	}
	STB_dep_SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
	for (i = 0; i < 20; i++) {
		digest[i] = (unsigned char)
		((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
	}
	/* Wipe variables */
	i = j = 0;
	memset(context->buffer, 0, 64);
	memset(context->state, 0, 20);
	memset(context->count, 0, 8);
	memset(&finalcount, 0, 8);
	#ifdef SHA1HANDSOFF  /* make SHA1Transform overwrite it's own static vars */
	STB_dep_SHA1Transform(context->state, context->buffer);
	#endif
}


#include <string.h>
#include <stdio.h>
#include <stdlib.h>


typedef struct{
	int digesttype;
	union{
		MD5_CTX md5;
		SHA1_CTX sha1;
	}type;
}g_digest;


#define STB_OK (0)
#define STB_ERROR (-1)
#define STB_PENDING (-2)


int STB_digest_init(int algorithm)
{
	int handle;
	g_digest *p = NULL;
	
	if((p = (g_digest *)malloc(sizeof(g_digest))) == NULL)
	{
		fprintf(stderr, "STB_digest_init: malloc error!\n");
		return 0;
	}
	memset(p, 0x00, sizeof(g_digest));
	if(algorithm == STB_DIGEST_MD5)
	{
		p->digesttype = STB_DIGEST_MD5;
		STB_dep_MD5Init(&p->type.md5);
	}
	else if(algorithm == STB_DIGEST_SHA1)
	{
		p->digesttype = STB_DIGEST_SHA1;
		STB_dep_SHA1Init(&p->type.sha1);
	}
	else
	{
		fprintf(stderr, "STB_digest_init: parameter algorithm error!\n");
		free(p);
		return 0;
	}

	handle = (int)p;
	return handle;
}


int STB_digest_update(int handle,unsigned char* data,unsigned int len)
{
	g_digest *p;
	
	if(handle == 0)
		return STB_ERROR;
	p = (g_digest *)handle;
	if(p->digesttype == STB_DIGEST_MD5)
	{
		STB_dep_MD5Update(&p->type.md5, data, len);
	}
	else if(p->digesttype == STB_DIGEST_SHA1)
	{
		STB_dep_SHA1Update(&p->type.sha1, data, len);
	}
	else{
		free(p);
		return STB_ERROR;
	}
	return STB_OK;
}

int STB_digest_final(int handle, unsigned char* digest, unsigned int len)
{
	g_digest *p;
	
	if(handle == 0)
		return STB_ERROR;
	
	p = (g_digest *)handle;
	memset(digest, 0x00, len);
	if(p->digesttype == STB_DIGEST_MD5)
	{
		if(len <16)
		{
			fprintf(stderr, "STB_digest_final: parameter len too little(must >=16byte)\n");
			free(p);
			return STB_ERROR;
		}
		STB_dep_MD5Final(digest, &p->type.md5);
		
	}
	else if(p->digesttype == STB_DIGEST_SHA1)
	{
		if(len <20)
		{
			fprintf(stderr, "STB_digest_final: parameter len too little(must >=20byte)\n");
			free(p);
			return STB_ERROR;
		}
		STB_dep_SHA1Final(digest, &p->type.sha1);
	}
	else{
		free(p);
		return STB_ERROR;
	}
	 free(p);
	return STB_OK;
}

/*******************************************************************
*MD5/SHA1 testing function
* @ argc =2£¬argv[1]=1(MD5) or 2(SHA1)£»
* #(Int): 
*testing value
   "a":0c c1 75 b9 c0 f1 b6 a8 31 c3 99 e2 69 77 26 61(MD5)
         86 f7 e4 37 fa a5 a7 fc e1 5d 1d dc b9 ea ea ea 37 76 67 b8(SHA1)
   "abc":90 01 50 98 3c d2 4f b0 d6 96 3f 7d 28 e1 7f 72 (MD5)
            a9 99 3e 36 47 06 81 6a ba 3e 25 71 78 50 c2 6c 9c d0 d8 9d(SHA1)
*/
#if 0
int main(int argc, char** argv)
{
	unsigned char digest[20], buffer[16384];
	FILE* file;
	int type;
	int handle;
	int len;
	int i;
	
	 if(argc != 2) {
        puts("debug:argc != 2");
        return 0;
    }
    type = atoi(argv[1]);
    if(type!=1&&type!=2)return 0;
    printf("type = %s\n", atoi(argv[1])==1?"MD5":"SHA1");
    handle = STB_digest_init(type);
    scanf("%s",buffer); 
    printf("input:%s\ndigest:",buffer);
    STB_digest_update(handle,buffer,strlen((char *)buffer)); 
    STB_digest_final(handle, digest, 20);
	len = (type==1)?16:20;
    for(i=0;i<len;i++)
    printf("%02x ",digest[i]);
    printf("\nlen = %d \nover!\n", len);
    return 0;
}
#endif

