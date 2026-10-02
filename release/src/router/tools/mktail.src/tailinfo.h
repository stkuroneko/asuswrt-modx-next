#ifndef __TAIL_INFO_H__
#define __TAIL_INFO_H__

/*
 *  tail format, header is in the bottom
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Contents...                                |
   |                    ...                                        |
   |                    ...                                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Type | Flags |Content Length1|        Content Length2        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Header Checksum       |        Content Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Magic Number (0x2afed414)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#include <asm/byteorder.h>
#define TAIL_MAGIC	0x2AFED414

typedef struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        uint8_t	flags:4,
		type:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        uint8_t	type:4,
		flags:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	uint8_t content_len_h;
	uint16_t content_len_l;
	uint16_t hdr_checksum;
	uint16_t content_checksum;
	uint32_t magic;
} __attribute__((packed)) basic_tailhdr_t;

typedef struct {
	uint32_t extendno;   // ASUSWRT full extendno
	uint16_t buildno;    // ASUSWRT buildno
	uint16_t reserved16; // 16bit reserved for future use
	uint32_t reserved32; // 32bit reserved for future use
} __attribute__((packed)) t1_content_t;

#endif
