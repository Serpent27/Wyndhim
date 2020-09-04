#ifndef PSEC_CRYPT_H
#define PSEC_CRYPT_H

/*
	This file refers to the 
			Wyndhim Encryption Algorithm
		not PARSEC
*/

#include "psec-crypt-options.h"
#include <stdint.h>

#ifdef TI84CE_BUILD
#include <tice.h>
#else
#ifdef LX_BUILD
#include <stdlib.h>
#define os_ClrHome() printf("\n")
#define os_GetStringInput(a, b, c) {printf(a); fgets(b, c, stdin);}
#define os_PutStrFull(a) printf(a)
#define os_GetCSC() 1
#endif
#endif
#include <stdio.h>
//#include <stdlib.h>

#ifdef TI84CE_BUILD
#define PSEC_INLINE
#else
#define PSEC_INLINE
//#define PSEC_INLINE extern inline
#endif

/* define worker functions */
#define ROLS(x, n, s) ((x << (n)) ^ (x >> (s - (n))))
#define RORS(x, n, s) ((x >> (n)) ^ (x << (s - (n))))
#define ROL(x, n) ROLS(x, n, 8)
#define ROR(x, n) RORS(x, n, 8)


#define _8BITS 0b11111111

#define MOD_BLK_SIZE ((1 << BLK_SIZE_BITS) - 1)
#define MOD_KEY_SIZE ((1 << KEY_SIZE_BITS) - 1)
#define MSG_SIZE  (MOD_BLK_SIZE + 1)
#define KEY_SIZE  (MOD_KEY_SIZE + 1)

const unsigned char hex_enc[] = "0123456789ABCDEF";
//unsigned char hex_dec[16];

const unsigned char round_combinator[] = {0x3A, 0x48, 0x9B, 0x95, 0xD7, 0xD6, 0xFA, 0x6A, 0x26, 0x71, 0xC0, 0x82, 0x32, 0xDE, 0x3C, 0xF4, 0xDF, 0xD2}; // this takes the place of an S-box. The round combinator is simply a string of random bytes, with length equal to `BLK_SIZE`

const unsigned char pbox_enc[] = {4, 7, 15, 6, 14, 8, 2, 0, 12, 1, 11, 3, 10, 5, 13, 9};
const unsigned char pbox_dec[] = {7, 9, 6, 11, 0, 13, 3, 1, 5, 15, 12, 10, 8, 14, 4, 2};
//const unsigned char pbox_enc[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0};
//const unsigned char pbox_dec[] = {15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};


//const unsigned char pbox_enc[] = {11, 16, 21, 6, 57, 10, 23, 8, 3, 5, 30, 38, 7, 46, 58, 33, 54, 9, 55, 1, 49, 41, 4, 13, 53, 17, 56, 39, 47, 20, 63, 59, 15, 48, 29, 12, 60, 35, 18, 42, 50, 61, 44, 36, 26, 0, 31, 14, 45, 22, 24, 25, 51, 37, 40, 19, 2, 52, 27, 28, 62, 43, 34, 32};
//const unsigned char pbox_dec[] = {45, 19, 56, 8, 22, 9, 3, 12, 7, 17, 5, 0, 35, 23, 47, 32, 1, 25, 38, 55, 29, 2, 49, 6, 50, 51, 44, 58, 59, 34, 10, 46, 63, 15, 62, 37, 43, 53, 11, 27, 54, 21, 39, 61, 42, 48, 13, 28, 33, 20, 40, 52, 57, 24, 16, 18, 26, 4, 14, 31, 36, 41, 60, 30};


/* Set maximum size of input and output buffers */
#define BLK_SIZE  MSG_SIZE
#define EXP_KEY_SIZE (BLK_SIZE * ROUNDS)
#define HASH_ITERS 1

#define KEY_IN_SIZE (KEY_SIZE * 2 + 2)
#define MSG_IN_SIZE (MSG_SIZE * 2 + 2)


PSEC_INLINE
void round_enc_sub(unsigned char *msg, unsigned char *key){
	size_t a;
	for(a=0; a<MSG_SIZE; ++a){
		msg[a] += a;
		msg[a] = ROL(msg[a], 3); // bit-rotate changes which bits are used in each operation
		msg[a] ^= key[a]; // mix the key into the message
		msg[a] += 0xFF;
		msg[a] ^= round_combinator[a]; // using addition/subtraction mixes the bits, making it nonlinear once they're split up and mixed with the key in the next round
	}
}
PSEC_INLINE
void round_dec_sub(unsigned char *msg, unsigned char *key){
	size_t a;
	for(a=0; a<MSG_SIZE; ++a){
		msg[a] ^= round_combinator[a];
		msg[a] -= 0xFF;
		msg[a] ^= key[a];
		msg[a] = ROR(msg[a], 3);
		msg[a] -= a;
	}
}
PSEC_INLINE
void round_mix(unsigned char *msg, unsigned char *tmp){
	size_t a;
	unsigned char b;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	//for(a=0; a<MSG_SIZE; ++a){
	//	tmp[a] = msg[a];
	//}
	for(a=0; a<MSG_SIZE; a += 2){
		b = msg[a];
		c = msg[(a + 1) & MOD_BLK_SIZE];
		d = (b & 0xAA) | (c & 0x55);
		e = (b & 0x55) | (c & 0xAA);
		msg[a] = d;
		msg[(a + 1) & MOD_BLK_SIZE] = e;
	}
}
PSEC_INLINE
void round_enc_per(unsigned char *msg, unsigned char *key, unsigned char *tmp){
	size_t a;
	unsigned char b = key[0] & MOD_BLK_SIZE;
	for(a=0; a<MSG_SIZE; ++a){
		tmp[a] = msg[a];
	}
	for(a=0; a<MSG_SIZE; ++a){
		msg[pbox_enc[a ^ b]] = tmp[a];
	}
}
PSEC_INLINE
void round_dec_per(unsigned char *msg, unsigned char *key, unsigned char *tmp){
	size_t a;
	unsigned char b = key[0] & MOD_BLK_SIZE;
	for(a=0; a<MSG_SIZE; ++a){
		tmp[a] = msg[a];
	}
	for(a=0; a<MSG_SIZE; ++a){
		msg[pbox_dec[a] ^ b] = tmp[a];
	}
}
PSEC_INLINE
void round_enc(unsigned char *msg, unsigned char *key, unsigned char *tmp){
	round_enc_sub(msg, key);
	round_enc_per(msg, key, tmp);
	round_mix(msg, tmp);
}
PSEC_INLINE
void round_dec(unsigned char *msg, unsigned char *key, unsigned char *tmp){
	round_mix(msg, tmp);
	round_dec_per(msg, key, tmp);
	round_dec_sub(msg, key);
}
PSEC_INLINE
void enc(unsigned char *msg, unsigned char *exp_key, unsigned char *tmp){
	size_t a;
	for(a=0; a<ROUNDS; ++a){
		round_enc(msg, &exp_key[a * MSG_SIZE], tmp);
	}
}
PSEC_INLINE
void dec(unsigned char *msg, unsigned char *exp_key, unsigned char *tmp){
	size_t a;
	for(a=ROUNDS; a>0; --a){
		round_dec(msg, &exp_key[(a-1) * MSG_SIZE], tmp);
	}
}

PSEC_INLINE
void expand_key(unsigned char *key, unsigned char *exp_key){
	size_t a;
	size_t b;
	for(a=0; a<EXP_KEY_SIZE; ++a){
		#ifdef PC_STATS
		exp_key[a] = 0;
		#else
		exp_key[a] = a;
		#endif
	}
	for(a=0; a<ROUNDS; ++a){
		for(b=0; b<KEY_SIZE; ++b){
			//os_ClrHome();
//			os_PutStrFull(text);
			exp_key[a * MSG_SIZE + b] ^= key[((a * 21) ^ b) & MOD_BLK_SIZE]; // 21 is prime, allowing for better shuffling of each round key
		}
	}
}

void encrypt(unsigned char *msg, unsigned char *key){
	unsigned char exp_key[EXP_KEY_SIZE];
	unsigned char tmp[MSG_SIZE];
//	char text[16];
	size_t a;
	size_t b;
	expand_key(key, exp_key);
	enc(msg, exp_key, tmp);
	for(a=0; a<KEY_SIZE; ++a){
		key[a] = 0;
	}
	for(a=0; a<MSG_SIZE; ++a){
		tmp[a] = 0;
		for(b=0; b<ROUNDS; ++b){
			//os_ClrHome();
			//os_PutStrFull(text);
			exp_key[b * MSG_SIZE + a] = 0;
		}
	}
}
void decrypt(unsigned char *msg, unsigned char *key){
	unsigned char exp_key[EXP_KEY_SIZE];
	unsigned char tmp[MSG_SIZE];
//	char text[16];
	size_t a;
	size_t b;
	expand_key(key, exp_key);
	dec(msg, exp_key, tmp);
	for(a=0; a<KEY_SIZE; ++a){
		key[a] = 0;
	}
	for(a=0; a<MSG_SIZE; ++a){
		tmp[a] = 0;
		for(b=0; b<ROUNDS; ++b){
			//os_ClrHome();
			//os_PutStrFull(text);
			exp_key[b * MSG_SIZE + a] = 0;
		}
	}
}
unsigned char hex_to_int(unsigned char c){
        unsigned char first = c / 16 - 3;
        unsigned char second = c % 16;
        unsigned char result = first*10 + second;
        if(result > 9) result--;
        return result;
}

void to_hex(unsigned char *input, unsigned char *output, const size_t size){
	size_t a;
	for(a=0; a<size; ++a){
		output[a * 2] = hex_enc[input[a] / 16];
		output[a * 2 + 1] = hex_enc[input[a] % 16];
		output[a * 2 + 2] = 0;
	}
}
void from_hex(unsigned char *input, unsigned char *output, const size_t size){
	size_t a;
	for(a=0; a<size; ++a){
		output[a] = hex_to_int(input[a * 2]) * 16;
		output[a] += hex_to_int(input[a * 2 + 1]);
	}
}
void hash_key(unsigned char *key){
	unsigned char exp_key[MSG_SIZE * ROUNDS];
	
}
void nop(unsigned char *key){
	// NOP
}


#endif
