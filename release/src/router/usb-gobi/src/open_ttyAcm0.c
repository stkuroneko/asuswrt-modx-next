/*
    Serial port I/O with /dev/ttyACM0 with none-Canonical Input Processing
    Sample usage:
        open_ttyAcm0 at+cops

    Limit:
        Max timeout is 25.5 seconds might failed when scan available networks.
    Author: Johnny Lin, ASKEY Corp., 2016.06.17
    Modifications:

*/
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* change this definition for the correct port */
#define     DefaultModemDevice     "ttyACM0"

/* baudrate settings are defined in <asm/termbits.h>,
    which is included by <termios.h> */
#define     BAUDRATE        B115200
#define     MaxBuffSize     1024
#define     VersionInfo     "V 1.0"

char        buf[MaxBuffSize], dBuf[MaxBuffSize];


int open_tty( struct termios *oldtio ) {
    struct termios  newtio;
    int  fileDesc;
    char dev[48];

    sprintf( dev, "/dev/%s", DefaultModemDevice );

    /*
      Open modem device for reading and writing and not as controlling tty
      because we don't want to get killed if linenoise sends CTRL-C.
    */
    fileDesc = open( dev, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fileDesc <0) {
        perror(dev);
        exit(-1);
    }

    // tty setting...
    tcgetattr(fileDesc, oldtio);    /* save current serial port settings */
    bzero(&newtio, sizeof(struct termios));  /* clear struct for new port settings */

    /* 控制模式
      BAUDRATE: Set bps rate. You could also use cfsetispeed and cfsetospeed.
      CRTSCTS : output hardware flow control (only used if the cable has
                all necessary lines. See sect. 7 of Serial-HOWTO)
      CS8     : 8n1 (8bit,no parity,1 stopbit)
      CLOCAL  : local connection, no modem contol
      CREAD   : enable receiving characters
      PARENB  : Enable parity generation on output and parity checking for input.
      CSTOPB  : Set two stop bits, rather than one.
      ==> 115200, N,8,1 enable receive, local connection
    */
    newtio.c_cflag = BAUDRATE | CRTSCTS | CS8 | CLOCAL | CREAD | ~PARENB | ~CSTOPB;

    /* 輸入模式
      IGNPAR  : ignore bytes with parity errors
      ICRNL   : map CR to NL (otherwise a CR input on the other computer
                will not terminate input)
      otherwise make device raw (no other input processing)
    */
    newtio.c_iflag = IGNPAR | ICRNL;

    /* 輸出模式 - Raw output.  */
    newtio.c_oflag = 0;

    /* 局部模式 --> 用來控制串列埠如何處理輸入字元
      ICANON  : enable canonical input, This enables the special characters
                EOF, EOL, EOL2, ERASE, KILL, LNEXT, REPRINT, STATUS, and WERASE,
                and buffers by lines.
      ISIG    :	When any of the characters INTR, QUIT, SUSP, or DSUSP
                are received, generate the corresponding signal.
      ECHO    : Echo input characters.
      ECHOE   :	If ICANON is also set, the ERASE character erases the preceding
                input character, and WERASE erases the preceding word.
    */
    newtio.c_lflag |= ~(ICANON | ECHO | ECHOE | ISIG);
    // newtio.c_lflag &= ~ICANON;     // Set non-canonical mode for timeout

    /*
      initialize all control characters
      default values can be found in /usr/include/termios.h,
      and are given in the comments, but we don't need them here
    */
    newtio.c_cc[VINTR]    = 0;     /* Ctrl-c */
    newtio.c_cc[VQUIT]    = 0;     /* Ctrl-\ */
    newtio.c_cc[VERASE]   = 0;     /* del */
    newtio.c_cc[VKILL]    = 0;     /* @ */
    newtio.c_cc[VEOF]     = 4;     /* Ctrl-d */
    // newtio.c_cc[VTIME] = 0;     /* inter-character timer unused */
    newtio.c_cc[VMIN]     = 1;     /* blocking read until 1 character arrives */
    newtio.c_cc[VSWTC]    = 0;     /* '\0' */
    newtio.c_cc[VSTART]   = 0;     /* Ctrl-q */
    newtio.c_cc[VSTOP]    = 0;     /* Ctrl-s */
    newtio.c_cc[VSUSP]    = 0;     /* Ctrl-z */
    newtio.c_cc[VEOL]     = 0;     /* '\0' */
    newtio.c_cc[VREPRINT] = 0;     /* Ctrl-r */
    newtio.c_cc[VDISCARD] = 0;     /* Ctrl-u */
    newtio.c_cc[VWERASE]  = 0;     /* Ctrl-w */
    newtio.c_cc[VLNEXT]   = 0;     /* Ctrl-v */
    newtio.c_cc[VEOL2]    = 0;     /* '\0' */

    /*
        VTIME - timeout value only used in non-canonical mode
        Set timeout in tenth seconds, e.g. 100 means 10 seconds,
        MAX is 25.5 seconds
    */
    newtio.c_cc[VTIME] = 255;
    /* now clean the modem line and activate the settings for the port */
    tcflush( fileDesc, TCIOFLUSH );         // flush I/O avoid strange data
    tcsetattr(fileDesc, TCSANOW, &newtio);  // TCSANOW - activate now

    return fileDesc;
}

int fnChkCmd( char *cmd ) {
    int iDiff = strcasecmp(cmd, "at+cops=?");
    // printf( "  CMD: %s --> %d\n", cmd, iDiff );
    if( iDiff==0 ) return 150;
    return 0;
}

int main( int argc, char *argv[]) {
    int  ii, fileDesc, res, iLen, iMaxWaits, iGot=0;
    char dev[128], *ptr, *pgn, *oPtr;
    struct termios  oldtio;
    struct timespec tsDelay, tsRem;

    ptr = DefaultModemDevice;
    pgn = argv[0];

    // check if parameters specified
    if( argc<=1 ) {
        // help message
        printf( "\n ----====< Serial port communication program %s >====----\n", VersionInfo );
        printf( "  Usage: %s {at-command}\n", pgn );
        printf( "  Sample usage: %s ate0\n", pgn );
        exit(0);
    }
    iMaxWaits = fnChkCmd(argv[1]);

    fileDesc = open_tty( &oldtio );

    // terminal settings done, now handle commands
    // get user command to write
    strcpy( buf, argv[1] );
    iLen = strlen( buf );
    // must add 13 manually, else no response
    buf[ iLen++ ] = 13;
    buf[ iLen ] = 0;

    res = write( fileDesc, buf, iLen );
    if( res - iLen ) {
        // no all written?
        //sprintf( dBuf, "Writes %d out of %d bytes!", res, iLen);
        //jLog( "%s", dBuf );
    }
    // else printf( " . Sent %d bytes. Reading...\n", res );

    // delay 0.2 second before reading response
    tsDelay.tv_sec  = 0;
    tsDelay.tv_nsec = 200000000;    // 0.2 sec
    nanosleep( &tsDelay, &tsRem );

    oPtr = buf;         // reset output for each command
    // loop to wait response
    do {
        // loop to read
        while( 1 ) {
            memset( buf, 0, MaxBuffSize );
            iLen = res = read( fileDesc, oPtr, MaxBuffSize-1 );
            if( iLen<0 ) {
                // no data got
                // printf( " NO DATA(%3d).\n", iMaxWaits );
                break;
            }
            if( iLen>0 ) {
                // set end of string, so we can use it as string
                oPtr[iLen] = 0;
                printf( "%s", oPtr );
                iGot++;
            }
            // delay 0.1 second before reading next response
            tsDelay.tv_sec  = 0;
            tsDelay.tv_nsec = 100000000;    // 0.1 sec
            nanosleep( &tsDelay, &tsRem );
        }
        // delay for next try to read when waiting data response
        if( --iMaxWaits > 0 && iGot==0 ) {
            // delay 2 second before reading next response
            tsDelay.tv_sec  = 2;
            tsDelay.tv_nsec = 500000000;    // 2.5 sec
            nanosleep( &tsDelay, &tsRem );            
        }
    } while( iMaxWaits > 0 && iGot==0 );

    /* restore the old port settings */
    tcsetattr(fileDesc,TCSANOW,&oldtio);
    close( fileDesc );
}
