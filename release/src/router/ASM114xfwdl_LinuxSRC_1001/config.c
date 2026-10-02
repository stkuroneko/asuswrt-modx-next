/*
 * Asmedia ASM2114 Firmware Configure Table Access Functions
 *
 * Copyright (C) 2015-2018 ASMedia Technology
 */

#include "precomp.h"

enum cfg_state g_cfg_state = CFG_GET_SECSSION;
cfg_item g_cfg_items[] =
{
    {"SVID", 0xcc, 0x02, SVID_ADDR, 0x174c, 0, 0},   // Subsystem Vendor ID
    {"SSID", 0xcc, 0x02, SSID_ADDR, 0x2114, 0, 0},   // Subsystem ID
};
#define CFG_ITEMS   ((int)(sizeof(g_cfg_items)/sizeof(g_cfg_items[0])))

str_item g_str_items[] =
{
    {"SVID", 0, 0, 0}, // Subsystem Vendor ID
    {"SSID", 0, 0, 0}, // Subsystem ID
    {"NEWFILE", 0, 0, 0},  // Create new binary file
    {"FWVERSION1", 0, 0, 0},   // FW version part 1
    {"FWVERSION2", 0, 0, 0},   // FW version part 2
};
#define STR_ITEMS   ((int)(sizeof(g_str_items)/sizeof(g_str_items[0])))

DWORD g_crctab[256];

static WORD get_cfg_section( char *line, WORD offset )
{
    WORD i;
    func_enter();

    for ( i = offset; i < MAX_LINE_SIZE && line[i]; i++ )
    {
        if ( line[i] == '/' && line[i+1] == '/' )
        {
            break;
        }
        else if ( line[i] == '[' )
        {
            if ( line[i+1] == 'C' && line[i+2] == 'u' && line[i+3] == 's' && line[i+4] == 't' )
            {
                g_cfg_state = CFG_GET_MEMBER;
                return i;
            }
        }
    }

    return i;
}

static WORD get_cfg_value( char *line, WORD offset, DWORD *cfg_value )
{
    WORD i;
    BYTE x;
    func_enter();

    *cfg_value = 0;
    for ( i = offset; i < MAX_LINE_SIZE && line[i]; i++ )
    {
        x = 0;
        if ( line[i] == '/' && line[i+1] == '/' )
        {
            break;
        }
        else if ( line[i] == '\t' || line[i] == ' ' || line[i] == '\n' )
        {
            continue;
        }
        else if ( line[i] == 'x' || line[i] == 'X' )
        {
            *cfg_value = 0;
            continue;
        }
        else if ( line[i] >= 'A' && line[i] <= 'F' )
        {
            x = line[i] - 'A' + 10;
        }
        else if ( line[i] >= 'a' && line[i] <= 'f' )
        {
            x = line[i] - 'a' + 10;
        }
        else if ( line[i] >= '0' && line[i] <= '9' )
        {
            x = line[i] - '0';
        }
	if (line[i]<0x30)// ignore ending characters
		continue;
        *cfg_value = ( *cfg_value << 4 ) | x;
	//printf("i=%d, x=%x, line[i]=%02x, *cfg_value=%x, end=%d \r\n",i, x, line[i], *cfg_value, MAX_LINE_SIZE && line[i]);
    }

    return i;
}

static WORD update_cfg_item_value( char *line, WORD offset, char *name )
{
    int i;
    func_enter();

    for ( i = 0; i < STR_ITEMS; i++ )
    {
        if ( !strcmp( name, g_str_items[i].name ) )
        {
            g_str_items[i].modified = 1;
            return get_cfg_value( line, offset, &g_str_items[i].value );
        }
    }

    return i;
}

static WORD get_cfg_member( char *line, WORD offset )
{
    WORD i, j;
    char member[128];
    func_enter();

    for ( i = offset, j = 0; i < MAX_LINE_SIZE && line[i]; i++ )
    {
        if ( line[i] == '[' )
        {
            g_cfg_state = CFG_GET_SECSSION;
            return get_cfg_section( line, i );
        }
        else if ( line[i] == '/' && line[i+1] == '/' )
        {
            break;
        }
        else if ( line[i] != '\t' && line[i] != ' ' )
        {
            if ( line[i] != '=' )
            {
                member[j++] = line[i];
            }
            else
            {
                member[j] = '\0';
                return update_cfg_item_value( line, i, member );
            }
        }
    }

    return i;
}

static cfg_item *find_cfg_item( char *name )
{
    int i;
    cfg_item *p = NULL;
    func_enter();

    for ( i = 0; i < CFG_ITEMS; i++ )
    {
        if ( !strcmp( name, g_cfg_items[i].name ) )
        {
            p = &g_cfg_items[i];
            break;
        }
    }

    return p;
}

static void sync_cfg_items( void )
{
    int i;
    cfg_item *p;
    str_item *s;
    func_enter();

    for ( i = 0; i < STR_ITEMS; i++ )
    {
        s = &g_str_items[i];
        if ( s->modified )
        {
            if ( !strncmp( s->name, "SVID", 4 ) ||
                    !strncmp( s->name, "SSID", 4 ) )
            {
                p = find_cfg_item( s->name );
                p->modified = 1;
                p->value = s->value;
            }
        }
    }
}

static str_item *find_str_item( char *name )
{
    int i;
    str_item *p = NULL;
    func_enter();

    for ( i = 0; i < STR_ITEMS; i++ )
    {
        if ( !strcmp( name, g_str_items[i].name ) )
        {
            p = &g_str_items[i];
            break;
        }
    }

    return p;
}
static DWORD crc32_reflect( DWORD ref, BYTE ch )
{
    int i;
    DWORD value = 0;
    func_enter();

    /* Swap bit 0 for bit 7 , bit 1 for bit 6, etc. */
    for ( i = 1; i < ( ch + 1 ); i++ )
    {
        if ( ref & 1 )
            { value |= 1 << ( ch - i ); }

        ref >>= 1;
    }

    return value;
}

void crc32_init( void )
{
    int i, j;
    DWORD polynomial = 0x04c11db7;
    func_enter();

    /* 256 values representing ASCII character codes. */
    for ( i = 0; i <= 0x0ff; i++ )
    {
        g_crctab[i] = crc32_reflect( i, 8 ) << 24;
        for ( j = 0; j < 8; j++ )
            { g_crctab[i] = ( g_crctab[i] << 1 ) ^ ( g_crctab[i] & ( 1 << 31 ) ? polynomial : 0 ); }

        g_crctab[i] = crc32_reflect( g_crctab[i], 32 );
    }
}

/*
 * The implementation then proceeds byte wise feeding the eight bit subtraction term in
 * at each stage along with the next eight bits of data. The code is:
 */
DWORD get_crc32( BYTE *buffer, DWORD size )
{
    DWORD len, crc = 0xfffffffful;
    func_enter();

    len = size;
    /*
     * Perform the algorithm on each character in the string,
     * using the lookup table values.
     */
    while ( len-- )
        { crc = ( crc >> 8 ) ^ g_crctab[( crc & 0x0ff ) ^ *buffer++]; }

    /* Exclusive OR the result with the beginning value. */
    return crc ^ 0xfffffffful;
}

BOOL cfgctl_read_config_file( void )
{
    FILE *file;
    char *ret;
    char line[MAX_LINE_SIZE];
    func_enter();

    file = fopen( "114xfw.cfg", "rt" );
    if ( NULL == file )
    {
        if ( verblevel )
            { printf( "Fail to open 114xfw.cfg\n" ); }

        return FALSE;
    }

    while ( 1 )
    {
        ret = fgets( line, MAX_LINE_SIZE, file );
        if ( NULL == ret )
        {
            break;
        }

        if ( CFG_GET_SECSSION == g_cfg_state )
        {
            get_cfg_section( line, 0 );
        }
        else if ( CFG_GET_MEMBER == g_cfg_state )
        {
            get_cfg_member( line, 0 );
        }
    }

    fclose( file );
    sync_cfg_items();
    return TRUE;
}

static BOOL cfgctl_get_newfile( void )
{
    str_item *p;
    func_enter();

    p = find_str_item( "NEWFILE" );
    if ( p )
        { return ( p->value ) ? TRUE : FALSE; }
    else
        { return FALSE; }
}

BYTE *cfgctl_update_config_table( const BYTE *inbuf )
{
    FILE *file;
    BYTE *outbuf;
    DWORD i, out_size, in_offset, out_offset, crc_value;
    BYTE checksum;
    BOOL newfile;

   BYTE data[8]={0};
   int ret = 0;

    func_enter();

    outbuf = ( BYTE * )malloc( 64 * 1024 );
    if ( NULL == outbuf )
    {
        if ( verblevel )
            { printf( "Fail to alloc memory\n" ); }

        return outbuf;
    }

    memset( outbuf, 0, 64 * 1024 );
    in_offset = ( ( WORD )inbuf[5] << 8 ) | inbuf[4];
    in_offset += 5;
    out_size = ( ( WORD )inbuf[in_offset + 1] << 8 ) | inbuf[in_offset];
    out_size += in_offset + 2 + 8 + 5;
    for ( i = 0; i < CFG_ITEMS; i++ )
    {
        if ( g_cfg_items[i].modified )
        {
            out_size += 8;
        }
    }

    /* Copy original configure table */
    in_offset = ( ( WORD )inbuf[5] << 8 ) | inbuf[4];
    memcpy( outbuf, inbuf, in_offset );
    out_offset = in_offset;
    for ( i = 0; i < CFG_ITEMS; i++ )
    {
        if ( g_cfg_items[i].modified )
        {
            outbuf[out_offset++] = g_cfg_items[i].head;
            outbuf[out_offset++] = g_cfg_items[i].type;
            outbuf[out_offset++] = g_cfg_items[i].address & 0x0ff;
            outbuf[out_offset++] = ( g_cfg_items[i].address >> 8 ) & 0x0ff;
            outbuf[out_offset++] = g_cfg_items[i].value & 0x0ff;
            outbuf[out_offset++] = ( g_cfg_items[i].value >> 8 ) & 0x0ff;
            outbuf[out_offset++] = ( g_cfg_items[i].value >> 16 ) & 0x0ff;
            outbuf[out_offset++] = ( g_cfg_items[i].value >> 24 ) & 0x0ff;
        }
    }

    outbuf[4] = out_offset & 0x0ff;
    outbuf[5] = ( out_offset >> 8 ) & 0x0ff;

    /* calculate checksum and CRC value of configure table */
    checksum = 0;
    for ( i = 0; i < out_offset; i++ )
    {
        checksum = ( checksum + outbuf[i] ) & 0x0ff;
    }

    outbuf[out_offset] = checksum;
    crc32_init();
    crc_value = get_crc32( outbuf, out_offset );
    out_offset++;
    outbuf[out_offset++] = crc_value & 0x0ff;
    outbuf[out_offset++] = ( crc_value >> 8 ) & 0x0ff;
    outbuf[out_offset++] = ( crc_value >> 16 ) & 0x0ff;
    outbuf[out_offset++] = ( crc_value >> 24 ) & 0x0ff;
    if ( verblevel )
        { printf( "cfg table checksum %x CRC %lx\n", checksum, crc_value ); }

    /* copy code body */
    in_offset += 5;
    outbuf[out_offset++] = inbuf[in_offset];
    outbuf[out_offset++] = inbuf[in_offset + 1];
    out_size = ( ( WORD )inbuf[in_offset + 1] << 8 ) | inbuf[in_offset];
    in_offset += 2;
    memcpy( &outbuf[out_offset], &inbuf[in_offset], out_size );

    /* calculate checksum and CRC value of code body */
    checksum = 0;
    for ( i = 0; i < out_size; i++ )
    {
        checksum = ( checksum + outbuf[out_offset + i] ) & 0x0ff;
    }

    crc32_init();
    crc_value = get_crc32( &outbuf[out_offset], out_size );
    out_offset += ( WORD )out_size;

	// read chip version
         ret = interctl_read_8051_memory(TYPE_XDATA, 0xf38C, 1, &data[0]);
        if (ret < 0) {
			printf("Fail read chip type %d\n",ret);
             return (BYTE * )inbuf;
        }

	if ( data[0] <0x10)
	{	// chip A
	//	U2114_FW
	    if (verblevel)
        	printf("modify chip A signature , data = %x\n", data[0]);

    outbuf[out_offset++] = 'U';
    outbuf[out_offset++] = '2';
    outbuf[out_offset++] = '1';
    outbuf[out_offset++] = '0';
    outbuf[out_offset++] = '4';
    outbuf[out_offset++] = '_';
    outbuf[out_offset++] = 'F';
    outbuf[out_offset++] = 'W';
	}
	else// 0x10~
	{	// Chip B
	    if (verblevel)
        	printf("modify chip B signature , data = %x\n", data[0]);

	    outbuf[out_offset++] = '2';
	    outbuf[out_offset++] = '1';
	    outbuf[out_offset++] = '0';
	    outbuf[out_offset++] = '4';
	    outbuf[out_offset++] = 'B';
	    outbuf[out_offset++] = '_';
	    outbuf[out_offset++] = 'F';
	    outbuf[out_offset++] = 'W';
	}
    outbuf[out_offset++] = checksum;
    outbuf[out_offset++] = crc_value & 0x0ff;
    outbuf[out_offset++] = ( crc_value >> 8 ) & 0x0ff;
    outbuf[out_offset++] = ( crc_value >> 16 ) & 0x0ff;
    outbuf[out_offset++] = ( crc_value >> 24 ) & 0x0ff;
    if ( verblevel )
        { printf( "code body checksum %x CRC %lx\n", checksum, crc_value ); }

    newfile = cfgctl_get_newfile();
    if ( TRUE == newfile )
    {
        file = fopen( "114xfw.new", "wb" );
        if ( file )
        {
            fwrite( outbuf, 1, 64 * 1024, file );
            fclose( file );
        }
        else if ( verblevel )
        {
            printf( "Fail to open 114xfw.new\n" );
        }
    }

    return outbuf;
}

WORD cfgctl_get_svid( void )
{
    cfg_item *p;
    func_enter();

    p = find_cfg_item( "SVID" );
    return ( p ) ? ( WORD )p->value : 0;
}

WORD cfgctl_get_ssid( void )
{
    cfg_item *p;
    func_enter();

    p = find_cfg_item( "SSID" );
    return ( p ) ? ( WORD )p->value : 0;
}

void cfgctl_get_fwversion( void *buffer )
{
    struct firmware_info *info = ( struct firmware_info * )buffer;
    str_item *p1, *p2;
    func_enter();

    memset( info, 0, sizeof( struct firmware_info ) );
    p1 = find_str_item( "FWVERSION1" );
    if ( p1 )
    {
        info->version[0] = ( p1->value >> 16 ) & 0xff;
        info->version[1] = ( p1->value >> 8 ) & 0xff;
        info->version[2] = p1->value & 0xff;
    }

    p2 = find_str_item( "FWVERSION2" );
    if ( p2 )
    {
        info->version[3] = ( p2->value >> 16 ) & 0xff;
        info->version[4] = ( p2->value >> 8 ) & 0xff;
        info->version[5] = p2->value & 0xff;
    }
}
