#ifndef _CRC16_H__
#define _CRC16_H__

/**
 * crc16 - compute the CRC-16 for the data buffer
 * @crc:        previous CRC value
 * @buffer:     data pointer
 * @len:        number of bytes in the buffer
 *
 * Returns the updated CRC value.
 */
 
unsigned short crc16(unsigned short crc, 
                     unsigned char const *buffer,
                     unsigned int len);


#endif // _CRC16_H__