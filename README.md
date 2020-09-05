# Wyndhim Encryption
#### Created by Alex Anderson < parsec29@protonmail.com >

*Wyndhim is based on the [PARSEC](https://github.com/Serpent27/PARSEC) encryption algorithm.*

### An important note:
I mention this elsewhere, but I want to make sure it's prominent: While my ego causes me to like to think this algorithm is ready for the big-leagues it's simply lacking the proper review. I emphasize that this algorithm is *experimental* and this algorithm is the very definition of homebrew crypto.

If you want to trust this algorithm for your secrets, you do so at your own risk...
*That said, if you like this algorithm or the idea behind it I'd love for someone to help with a proper cryptanalysis!*

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


------------------------------------------------
### It looks like I decided to explain myself...

So, why is this algorithm made how it's made?

If you notice above, I used the bitmask `0b10101010/0b01010101` to provide diffusion. I could have chosen 0b00001111/0b11110000, 0b10010011/0b01101100, etc; but I chose a very boring alternating pattern of `0`s and `1`s. Why?

If you look at the S-Box-like operation I perform the most nonlinear part is an addition; making the S-Box (more than) slightly less-than-ideal. The reason I did this instead of implementing a proper S-Box is to prevent the need for lookup tables, or any non-constant-time operation. I didn't even like having the `ADD`s in there because I don't trust hardware manufacturers to keep their microcode constant-time, even for the most basic of operations. As such, the choice is to embrace timing attacks, speculative execution, etc; or sacrifice the S-Box in hopes that I can make up for it in other ways.

If you know much about binary addition you'll know that any 2 bits that are both HIGH (1+1) will affect the position immediately more significant than them in the output. For this reason, I used an `ADD byte m[i], 0xFF` to propogate changes to nearby bits. I also used an XOR (actually 2 XORs) to create nonlinearity in which bits get flipped. Then, every flipped bit gets whisked away to meet up with other bits from somewhere else in the cipher; this way nonlinearity comes from the differences of which bits get moved where, instead of relying on the S-Box for that effect. Instead of using nonlinear operations I opted to use separate linear operations that fail to interact linearly when combined.

For example, raising to an exponent is just repeated multiplication; multiplication is just repeated addition; and addition is as linear as an operation gets. But the way you use it causes it to *become* nonlinear. An XOR is linear, and an ADD is linear, but the operations mess with each others' mechanics to create something distinctly nonlinear. Then, you take half the bits, replace them with bits from an entirely separate part of the message, then do it again. See where I'm going with this?

Imagine the polynomial `y=(x-5)(x-2)(x+8)(x-4)(x+7) + k`. That's a pretty linear system, and easy to work with. But what if I changed it to `y=((x XOR z)-5)(x-2)(x XOR z)(x-4)((x+7) XOR z) + k`? Would it help if I said `z=8`? It's Galois field arithmetic mixed with regular arithmetic. Each simple enough: they're both linear, but they don't play well together.

Then all I need to do is propogate those nonlinearities as far as possible as fast as possible. Hence I used `10101010` as my bitmask - it's got more surface area to propogate changes.

#### In short,
I'm proposing we mix Galois fields with traditional arithmetic. Or more generally, mix things that don't like mixing - after all, isn't that what cryptography's all about?


*And it's only using constant-time operations.*



(At least that's the idea)
