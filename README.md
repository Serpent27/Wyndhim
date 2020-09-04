# Windhym Encryption
#### Created by Alex Anderson < parsec29@protonmail.com >

*Wyndhim is based on the [PARSEC](https://github.com/Serpent27/PARSEC) encryption algorithm.*

### What is Wyndhim?

Wyndhim is an experimental attempt at an SP-network without an S-Box.

Let's start with the issue affecting most SP-Networks implemented on modern systems: cache-timing attacks. SP-Networks are based on substitutions and permutations, which are designed to destroy patterns and make the ciphertext as random as possible, even if the input has very strong patterns. This is, in general, a good system; except S-Boxes usually require table-lookups in RAM. This wouldn't be a big deal if you could manually control what data gets put in cache, but most processors require that to be done in kernel-mode, making userland implementations anywhere from annoying to impractical.

***But**, what if you could derive an S-Box from a P-box?*

Let me explain,

When I was implementing PARSEC I used the following code to provide diffusion:
```
for(a=0; a<BLOCK_SIZE; a+=2){
	blk_out[a]   = (blk[a]   & 0b10101010) | (blk[a+1] & 0b01010101)
	blk_out[a+1] = (blk[a+1] & 0b01010101) | (blk[a]   & 0b10101010)
}
```

I thought, if I can split up the bits and use simple linear operations (bit-rotates, XORs, and addition) to randomize how the bits are mixed, maybe I can use that to replace an S-Box.

*Technically* Wyndhim has an S-Box (comprised of an ADD, ROT, XOR[key], ADD, XOR), but since the S-Box isn't meant to be too secure without other permutation-related tricks beyond a normal SP-Network, I don't really consider it an S-Box. The purpose of the ADDs are to provide nonlinearity and contrast the XORs (ADD + XOR -> nonlinear-ish; ADD + ROT + XOR + ADD + XOR -> close enough?).

The ADDs propogate changes between bits and those changes get split and distributed among the rest of the message. AKA it's a normal SP-Network except with less emphasis on the *substitution* and more emphasis on *permutation*. Since I still need a reasonable amount of substitution to prevent it from becoming the world's most ridiculous extension of Vigenere, I used the S-Box simply to allow the permutation to create the effect of better substitution.

I could go on about the design rationale (for example, why I chose to use 0b10101010/0b01010101 as the bitmask for diffusion and not 0b00001111/0b11110000, 0b10010011/0b01101100, etc) but I'm getting tired so maybe I'll release an update tomorrow to explain... Or maybe not, who knows?
