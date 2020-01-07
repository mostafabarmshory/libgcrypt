/*
 * 3- Add the cipher implementation
 *
 * Test values:
 *
 */

// Globals
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "cipher-selftest.h"

#define XOR_CIPHER_BLOCK_SIZE 16
#define XOR_CIPHER_BLOCK_LEN 128
#define XOR_CIPHER_KEY_SIZE 16
#define XOR_CIPHER_KEY_LEN 128

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

typedef struct {
	byte key[XOR_CIPHER_KEY_SIZE];
} XorContext;

static gcry_err_code_t bf_setkey(void *c, const byte *key, unsigned keylen);
static unsigned int encrypt_block(void *bc, byte *outbuf, const byte *inbuf);
static unsigned int decrypt_block(void *bc, byte *outbuf, const byte *inbuf);

/*
 * Set key into the cipher context
 */
static gcry_err_code_t bf_setkey(void *context, const byte *key, unsigned keylen) {
	XorContext *c = (XorContext*) context;
	memset(c, 0x0, sizeof(XorContext));
	memcpy(c->key, key, MIN(keylen, XOR_CIPHER_KEY_SIZE));
	return GPG_ERR_NO_ERROR;
}

/*
 * Encrypt a block
 */
static unsigned int encrypt_block(void *context, byte *outbuf, const byte *inbuf) {
	XorContext *c = (XorContext*) context;
	for(int i = 0x0; i < XOR_CIPHER_BLOCK_SIZE; i++){
		outbuf[i] = inbuf[i] ^ c->key[i];
	}
	return (XOR_CIPHER_BLOCK_LEN);
}

/*
 * Decrypt a block
 *
 * Decrypt block with context and return the length of the block in
 * bit.
 */
static unsigned int decrypt_block(void *context, byte *outbuf, const byte *inbuf) {
	XorContext *c = (XorContext*) context;
	for(int i = 0x0; i < XOR_CIPHER_BLOCK_SIZE; i++){
		outbuf[i] = inbuf[i] ^ c->key[i];
	}
	return (XOR_CIPHER_BLOCK_LEN);
}

/*
 * 3- Define cipher
 *
 * This is cipher XOR definitions.
 */
gcry_cipher_spec_t _gcry_cipher_spec_xor = {
		// Cipher ID
		GCRY_CIPHER_XOR,
		// Cipher flags
		{
				0, //<- Disabled
				0  //<- FIPS
		},
		// Cipher name
		"XOR",
		// Cipher aliases
		NULL,
		// Cipher OID
		NULL,
		// Cipher Block Size (byte)
		XOR_CIPHER_BLOCK_SIZE,
		// Cipher key length (bit)
		XOR_CIPHER_KEY_LEN,
		// Cipher context size
		sizeof(XorContext),
		// Cipher set key function (void *c, const unsigned char *key, unsigned keylen) -> gcry_err_code_t
		bf_setkey,
		// Cipher encrypt block function (void *c, unsigned char *outbuf, const unsigned char *inbuf) -> int
		encrypt_block,
		// Cipher decrypt block function (void *c, unsigned char *outbuf, const unsigned char *inbuf) -> int
		decrypt_block
};
