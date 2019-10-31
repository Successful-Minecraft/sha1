/*********************************************************************
* Filename:   sha1_test.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding SHA1
			  implementation. These tests do not encompass the full
			  range of available test vectors, however, if the tests
			  pass it is very, very likely that the code is correct
			  and was compiled properly. This code also serves as
			  example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/

#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>
#include <stddef.h>
/****************************** MACROS ******************************/
#define SHA1_BLOCK_SIZE 20              // SHA1 outputs a 20 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[5];
	WORD k[4];
} SHA1_CTX;



/****************************** MACROS ******************************/
#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))

/*********************** FUNCTION DEFINITIONS ***********************/
void sha1_transform(SHA1_CTX* ctx, const BYTE data[])
{
	WORD a, b, c, d, e, i, j, t, m[80];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j + 3]);
	for (; i < 80; ++i) {
		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31);
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	for (i = 0; i < 20; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for (; i < 40; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for (; i < 60; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for (; i < 80; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

void sha1_init(SHA1_CTX* ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0] = 0x5a827999;
	ctx->k[1] = 0x6ed9eba1;
	ctx->k[2] = 0x8f1bbcdc;
	ctx->k[3] = 0xca62c1d6;
}

void sha1_update(SHA1_CTX* ctx, const BYTE data[], size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha1_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha1_final(SHA1_CTX* ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha1_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += (int)ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha1_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and MD uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}
}


/*********************** FUNCTION DEFINITIONS ***********************/
int sha1_test()
{
	BYTE text1[] = { "abc" };
	BYTE text2[] = { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" };
	BYTE text3[] = { "aaaaaaaaaa" };
	BYTE hash1[SHA1_BLOCK_SIZE] = { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d };
	BYTE hash2[SHA1_BLOCK_SIZE] = { 0x84,0x98,0x3e,0x44,0x1c,0x3b,0xd2,0x6e,0xba,0xae,0x4a,0xa1,0xf9,0x51,0x29,0xe5,0xe5,0x46,0x70,0xf1 };
	BYTE hash3[SHA1_BLOCK_SIZE] = { 0x34,0x95,0xff,0x69,0xd3,0x46,0x71,0xd1,0xe1,0x5b,0x33,0xa6,0x3c,0x13,0x79,0xfd,0xed,0xd3,0xa3,0x2a };
	BYTE buf[SHA1_BLOCK_SIZE];
	int idx;
	SHA1_CTX ctx;
	int pass = 1;
	int i = 0;


	sha1_init(&ctx);
	sha1_update(&ctx, text1, 3);
	sha1_final(&ctx, buf);
	pass = pass && !memcmp(hash1, buf, SHA1_BLOCK_SIZE);
	

	

	sha1_init(&ctx);
	sha1_update(&ctx, text2, 56);
	sha1_final(&ctx, buf);
	pass = pass && !memcmp(hash2, buf, SHA1_BLOCK_SIZE);

	sha1_init(&ctx);
	sha1_update(&ctx, text3, 10);
	sha1_final(&ctx, buf);
	pass = pass && !memcmp(hash3, buf, SHA1_BLOCK_SIZE);

	return(pass);
}

struct note {
	BYTE index;
	struct note* next=NULL;
};

note** construct() {
	int i = 0;
	struct note** temp = (note **) malloc(256 * sizeof(note * ));
	for (i = 0; i < 256; ++i) {
		temp[i] = (note *)malloc(sizeof(note*));
		temp[i]->index = (BYTE)i;
		temp[i]->next = NULL;
		printf("% hu  ", temp[i]->index);
	}
	return temp;

}

inline bool addmore(struct note** head0, BYTE* output,int firstNnibbles) {
	int size = 20;
	int i = 0, j = 0, k = 0;
	if (head0[output[0]]->next != NULL);
	else {
		note* newnote = (note*)malloc(sizeof(note));
		head0[output[0]]->next = newnote;
		newnote->next = NULL;
	}
	for (i = 1; i < size; ++i) {
		newnote->index = output[i];
			if (newnote->next != NULL) {
				newnote = newnote->next;
				printf("\nif1\n");
			}
			else {
				note* newnote2 = (note*)malloc(sizeof(note));
				newnote2->next = NULL;
				newnote->next = newnote2;
				newnote = newnote2;
				printf("\nif2\n");
			}
		
	}
	return false;
}

int main()
{
	/*
	printf("SHA1 tests: %s\n", sha1_test() ? "SUCCEEDED" : "FAILED");
	printf("\n%c\n\n%c\n\n%c\n\n%c\n\n%c\n", (char)(BYTE)63, 64, 65, 66, 67);
	*/
	/*
	BYTE buf[SHA1_BLOCK_SIZE];
	SHA1_CTX ctx;
	BYTE b[] = {"abc"};
	int i = 0, j = 0, k = 0, l = 0;
	for (i = 0; i < 20; ++i) {
		for (j = 0; j < 30; ++j) {
			for (k = 0; k <50; ++k) {
				b[0] = (char)i;
				b[1] = (char)j;
				b[2] = (char)k;
				sha1_init(&ctx);
				sha1_update(&ctx, b, 3);
				sha1_final(&ctx, buf);
				for (l = 0; l < 20; ++l)
					printf("%.4d", buf[l]);
				printf("\n");
			}
		}
	}
	*/
	struct note** head0 = NULL;
	head0 = construct();
	BYTE hash1[SHA1_BLOCK_SIZE] = { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d };
	BYTE hash2[SHA1_BLOCK_SIZE] = { 0x84,0x98,0x3e,0x44,0x1c,0x3b,0xd2,0x6e,0xba,0xae,0x4a,0xa1,0xf9,0x51,0x29,0xe5,0xe5,0x46,0x70,0xf1 };
	printf("%d", addmore(head0, hash1, 3));
	printf("%d", addmore(head0, hash1, 3));
	//addmore(head0, hash2,3);
	struct note* pointer = NULL;

	pointer = head0[hash1[0]];
	for (int i = 0; i < 20; ++i) {
		if (pointer->next != NULL) {
			printf("\n%.4x\n", pointer->index);
			pointer = pointer->next;
		}
		else break;
	}
	printf("\n\n\n\n\n\n\n\n\n");

	return(0);
}
