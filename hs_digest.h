#ifndef __STB_DIGEST_H__
#define __STB_DIGEST_H__

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* MD5 context. */
typedef struct {
  /* state (ABCD) */
  unsigned long state[4];

  /* number of bits, modulo 2^64 (lsb first) */
  unsigned long count[2];

  /* input buffer */
  unsigned char buffer[64];
} MD5_CTX;

/* SHA1 context. */
typedef struct {
	unsigned long state[5];
	unsigned long count[2];
	unsigned char buffer[64];
} SHA1_CTX;


enum{
	STB_DIGEST_MD5=1,
	STB_DIGEST_SHA1
};


int STB_digest_init(int algorithm);
int STB_digest_update(int handle,unsigned char* data,unsigned int len);
int STB_digest_final(int handle, unsigned char* digest, unsigned int len);


#endif/*__STB_DIGEST_H__*/
