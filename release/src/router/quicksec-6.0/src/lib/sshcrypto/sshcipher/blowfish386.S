/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Blowfish encryption and decryption in GCC assembler version for i386
   processors.
*/

	.file "blowfish386.S"
	.text
		.align 2
	.globl ssh_blowfish_encrypt
		.type ssh_blowfish_encrypt, @function
	.globl _ssh_blowfish_encrypt
		.type _ssh_blowfish_encrypt, @function

ssh_blowfish_encrypt:
_ssh_blowfish_encrypt:
	pushl %ebp
	movl %esp, %ebp

	pushl %ebx
	pushl %esi
	pushl %edi

#define CTX 8(%ebp)
#define XL  12(%ebp)
#define XR  16(%ebp)
#define OUTPUT 20(%ebp)

	movl CTX, %esi  /* Get the address of S box */
	movl %esi, %edi
	addl $(1024*4), %edi /* Get the address of P box */

	movl XL, %eax	/* Place XL to eax (need to convert lsb first) */

	movl XR, %ebx   /* Place XR to ebx (need to convert lsb first) */

	xorl (%edi), %eax /* Do the XL ^= P[0] first */
        xorl %ecx, %ecx   /* Clear the index variable */

#define ROUND(n)                         \
	roll $16, %eax;                  \
	movb %ah, %cl;                   \
	movl (%esi, %ecx, 4), %edx;      \
	                                 \
	movb %al, %cl;                   \
	addl 256*4(%esi, %ecx, 4), %edx; \
                                         \
	roll $16, %eax;                  \
	movb %ah, %cl;                   \
	xorl 512*4(%esi, %ecx, 4), %edx; \
                                         \
	movb %al, %cl;                   \
	addl 768*4(%esi, %ecx, 4), %edx; \
                                         \
	xorl n*4(%edi), %edx;            \
                                         \
	xorl %edx, %ebx;                 \
        /* SWAP */                       \
	roll $16, %ebx;                  \
	movb %bh, %cl;                   \
	movl (%esi, %ecx, 4), %edx;      \
	                                 \
	movb %bl, %cl;                   \
	addl 256*4(%esi, %ecx, 4), %edx; \
                                         \
	roll $16, %ebx;                  \
	movb %bh, %cl;                   \
	xorl 512*4(%esi, %ecx, 4), %edx; \
                                         \
	movb %bl, %cl;                   \
	addl 768*4(%esi, %ecx, 4), %edx; \
                                         \
	xorl ((n+1)*4)(%edi), %edx;        \
                                         \
	xorl %edx, %eax;

	/* ROUNDS */
	ROUND(1)
	ROUND(3)
	ROUND(5)
	ROUND(7)
	ROUND(9)
	ROUND(11)
	ROUND(13)
	ROUND(15)
#undef ROUND

	/* The final XR ^= P[17] */

	xorl 17*4(%edi), %ebx

	movl OUTPUT, %esi

      	movl %ebx, (%esi)
	movl %eax, 4(%esi)

	/* Finish it off */
	popl %edi
	popl %esi
	popl %ebx

	/* Correct the stack pointer */
	movl %ebp, %esp
	popl %ebp
	ret

      		.align 2
	.globl ssh_blowfish_decrypt
		.type ssh_blowfish_decrypt, @function
	.globl _ssh_blowfish_decrypt
		.type _ssh_blowfish_decrypt, @function

ssh_blowfish_decrypt:
_ssh_blowfish_decrypt:
       	pushl %ebp
	movl %esp, %ebp

	pushl %ebx
	pushl %esi
	pushl %edi

#define CTX 8(%ebp)
#define XL  12(%ebp)
#define XR  16(%ebp)
#define OUTPUT 20(%ebp)

	movl CTX, %esi  /* Get the address of S box */
	movl %esi, %edi
	addl $(1024*4), %edi /* Get the address of P box */

	movl XL, %eax	/* Place XL to eax (need to convert lsb first) */

	movl XR, %ebx   /* Place XR to ebx (need to convert lsb first) */

	xorl 17*4(%edi), %eax /* Do the XL ^= P[17] first */
        xorl %ecx, %ecx   /* Clear the index variable */

#define ROUND(n)                         \
	roll $16, %eax;                  \
	movb %ah, %cl;                   \
	movl (%esi, %ecx, 4), %edx;      \
	                                 \
	movb %al, %cl;                   \
	addl 256*4(%esi, %ecx, 4), %edx; \
                                         \
	roll $16, %eax;                  \
	movb %ah, %cl;                   \
	xorl 512*4(%esi, %ecx, 4), %edx; \
                                         \
	movb %al, %cl;                   \
	addl 768*4(%esi, %ecx, 4), %edx; \
                                         \
	xorl n*4(%edi), %edx;            \
                                         \
	xorl %edx, %ebx;                 \
        /* SWAP */                       \
	roll $16, %ebx;                  \
	movb %bh, %cl;                   \
	movl (%esi, %ecx, 4), %edx;      \
	                                 \
	movb %bl, %cl;                   \
	addl 256*4(%esi, %ecx, 4), %edx; \
                                         \
	roll $16, %ebx;                  \
	movb %bh, %cl;                   \
	xorl 512*4(%esi, %ecx, 4), %edx; \
                                         \
	movb %bl, %cl;                   \
	addl 768*4(%esi, %ecx, 4), %edx; \
                                         \
	xorl (n-1)*4(%edi), %edx;        \
                                         \
	xorl %edx, %eax;

	/* ROUNDS */
	ROUND(16)
	ROUND(14)
	ROUND(12)
	ROUND(10)
	ROUND(8)
	ROUND(6)
	ROUND(4)
	ROUND(2)
#undef ROUND

	/* The final XR ^= P[0] */

	xorl (%edi), %ebx

	movl OUTPUT, %esi

      	movl %ebx, (%esi)
	movl %eax, 4(%esi)

	/* Get pushed */
	popl %edi
	popl %esi
	popl %ebx

	/* Correct the stack pointer */
	movl %ebp, %esp
	popl %ebp
	ret
