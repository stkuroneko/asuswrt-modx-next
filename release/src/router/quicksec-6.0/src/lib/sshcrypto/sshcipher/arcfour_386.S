/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   alleged-RC4 GNU assembler implementation

   Further optimizations are very difficult to do due simplicity of
   the innerloop.
*/

	.file "rc4_386.S"
	.text

	.align 2
	.globl ssh_arcfour_transform
	.type ssh_arcfour_transform, @function
	.globl _ssh_arcfour_transform
	.type _ssh_arcfour_transform, @function

ssh_arcfour_transform:
_ssh_arcfour_transform:

	pushl %ebp
	movl %esp, %ebp

	pushl %ebx
	pushl %esi
	pushl %edi

#define CTX 8(%ebp)
#define DEST 12(%ebp)
#define SRC  16(%ebp)
#define LEN  20(%ebp)
#define IV   24(%ebp)

	movl CTX, %edi

	movl (%edi), %eax
	andl $255, %eax
	movl 4(%edi), %ebx
	andl $255, %ebx

	addl $8, %edi

	movl LEN, %ecx
	movl SRC, %esi
	movl DEST, %edx

	pushl %ebp
	movl %edx, %ebp
	xorl %edx, %edx

	testl %ecx, %ecx
	jz end_arcfour_loop

arcfour_loop:
	/* Get byte */
	incb %al
	movb (%edi, %eax), %dl
	addb %dl, %bl
	movb (%edi, %ebx), %dh

	movb %dl, (%edi, %ebx)
	movb %dh, (%edi, %eax)

	addb %dh, %dl
	xorb %dh, %dh

	/* Could ah be substituted by any other byte register? */
	movb (%edi, %edx), %ah

        /* DEST = SRC XOR ARCFOUR_BYTE */

	xorb (%esi), %ah
	movb %ah, (%ebp)
        xorb %ah, %ah

	incl %esi
	incl %ebp
	decl %ecx
	jnz arcfour_loop

end_arcfour_loop:

	popl %ebp

	movl CTX, %edi

	movl %eax, (%edi)
	movl %ebx, 4(%edi)

	popl %edi
	popl %esi
	popl %ebx

	movl %ebp, %esp
	popl %ebp
	ret
