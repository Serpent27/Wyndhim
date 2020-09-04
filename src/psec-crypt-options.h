#ifndef PSEC_CRYPT_OPTIONS_H
#define PSEC_CRYPT_OPTIONS_H

#define BLK_SIZE_BITS 4 // Block size = 2^4 =  16 bytes =  128 bits, Yes I know the notation is weird
#define KEY_SIZE_BITS 5 // Key   size = 2^5 =  32 bytes =  256 bits, Yes I know the notation is weird
#define ROUNDS    32    // 32 rounds, to be extra secure

#define ENCRYPT		// build ENCRYPTion code
#define DECRYPT		// build DECRYPTion code
#define HASH		// build HASH code
			// currently only hashes 1 block of data, but it's simple enough to change that.
			// I have comments in 'main.c' explaining how
//#define OP_TEST		// build performance test code
			// Runs single-core encryption using the current settings	
#define ENCDEC_CHOICE	// Provides the user with a menu to choose operation
			// [E]ncrypt/[D]ecrypt/[H]ash/[T]est
//#define LX_BUILD	// Build for Linux/Unix/*nix targets
			// This should work for Windows too, although I've never tried
#define TI84CE_BUILD	// This code was originally designed for the TI-84+CE calculators,
			// although an optimization I made to improve security against timing-attacks
			// broke the TI-84+CE build. Maybe sometime I'll fix the TI-84+CE build...?
//#define PC_STATS

#endif
