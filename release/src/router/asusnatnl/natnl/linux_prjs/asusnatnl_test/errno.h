#ifndef __ERRNO_H__
#define __ERRNO_H__


/*******************************PJ ERRNO*******************************/
/**
 * @hideinitializer
 * Unknown error has been reported.
 */
#define PJ_EUNKNOWN	    (PJ_ERRNO_START_STATUS + 1)	/* 70001 */
/**
 * @hideinitializer
 * The operation is pending and will be completed later.
 */
#define PJ_EPENDING	    (PJ_ERRNO_START_STATUS + 2)	/* 70002 */
/**
 * @hideinitializer
 * Too many connecting sockets.
 */
#define PJ_ETOOMANYCONN	    (PJ_ERRNO_START_STATUS + 3)	/* 70003 */
/**
 * @hideinitializer
 * Invalid argument.
 */
#define PJ_EINVAL	    (PJ_ERRNO_START_STATUS + 4)	/* 70004 */
/**
 * @hideinitializer
 * Name too long (eg. hostname too long).
 */
#define PJ_ENAMETOOLONG	    (PJ_ERRNO_START_STATUS + 5)	/* 70005 */
/**
 * @hideinitializer
 * Not found.
 */
#define PJ_ENOTFOUND	    (PJ_ERRNO_START_STATUS + 6)	/* 70006 */
/**
 * @hideinitializer
 * Not enough memory.
 */
#define PJ_ENOMEM	    (PJ_ERRNO_START_STATUS + 7)	/* 70007 */
/**
 * @hideinitializer
 * Bug detected!
 */
#define PJ_EBUG             (PJ_ERRNO_START_STATUS + 8)	/* 70008 */
/**
 * @hideinitializer
 * Operation timed out.
 */
#define PJ_ETIMEDOUT        (PJ_ERRNO_START_STATUS + 9)	/* 70009 */
/**
 * @hideinitializer
 * Too many objects.
 */
#define PJ_ETOOMANY         (PJ_ERRNO_START_STATUS + 10)/* 70010 */
/**
 * @hideinitializer
 * Object is busy.
 */
#define PJ_EBUSY            (PJ_ERRNO_START_STATUS + 11)/* 70011 */
/**
 * @hideinitializer
 * The specified option is not supported.
 */
#define PJ_ENOTSUP	    (PJ_ERRNO_START_STATUS + 12)/* 70012 */
/**
 * @hideinitializer
 * Invalid operation.
 */
#define PJ_EINVALIDOP	    (PJ_ERRNO_START_STATUS + 13)/* 70013 */
/**
 * @hideinitializer
 * Operation is cancelled.
 */
#define PJ_ECANCELLED	    (PJ_ERRNO_START_STATUS + 14)/* 70014 */
/**
 * @hideinitializer
 * Object already exists.
 */
#define PJ_EEXISTS          (PJ_ERRNO_START_STATUS + 15)/* 70015 */
/**
 * @hideinitializer
 * End of file.
 */
#define PJ_EEOF		    (PJ_ERRNO_START_STATUS + 16)/* 70016 */
/**
 * @hideinitializer
 * Size is too big.
 */
#define PJ_ETOOBIG	    (PJ_ERRNO_START_STATUS + 17)/* 70017 */
/**
 * @hideinitializer
 * Error in gethostbyname(). This is a generic error returned when
 * gethostbyname() has returned an error.
 */
#define PJ_ERESOLVE	    (PJ_ERRNO_START_STATUS + 18)/* 70018 */
/**
 * @hideinitializer
 * Size is too small.
 */
#define PJ_ETOOSMALL	    (PJ_ERRNO_START_STATUS + 19)/* 70019 */
/**
 * @hideinitializer
 * Ignored
 */
#define PJ_EIGNORED	    (PJ_ERRNO_START_STATUS + 20)/* 70020 */
/**
 * @hideinitializer
 * IPv6 is not supported
 */
#define PJ_EIPV6NOTSUP	    (PJ_ERRNO_START_STATUS + 21)/* 70021 */
/**
 * @hideinitializer
 * Unsupported address family
 */
#define PJ_EAFNOTSUP	    (PJ_ERRNO_START_STATUS + 22)/* 70022 */

/** @} */   /* pj_errnum */

/** @} */   /* pj_errno */


/**
 * PJ_ERRNO_START is where PJLIB specific error values start.
 */
#define PJ_ERRNO_START		20000

/**
 * PJ_ERRNO_SPACE_SIZE is the maximum number of errors in one of 
 * the error/status range below.
 */
#define PJ_ERRNO_SPACE_SIZE	50000

/**
 * PJ_ERRNO_START_STATUS is where PJLIB specific status codes start.
 * Effectively the error in this class would be 70000 - 119000.
 */
#define PJ_ERRNO_START_STATUS	(PJ_ERRNO_START + PJ_ERRNO_SPACE_SIZE)

/**
 * PJ_ERRNO_START_SYS converts platform specific error codes into
 * pj_status_t values.
 * Effectively the error in this class would be 120000 - 169000.
 */
#define PJ_ERRNO_START_SYS	(PJ_ERRNO_START_STATUS + PJ_ERRNO_SPACE_SIZE)

/**
 * PJ_ERRNO_START_USER are reserved for applications that use error
 * codes along with PJLIB codes.
 * Effectively the error in this class would be 170000 - 219000.
 */
#define PJ_ERRNO_START_USER	(PJ_ERRNO_START_SYS + PJ_ERRNO_SPACE_SIZE)



/**
 * Start of error code relative to PJ_ERRNO_START_USER.
 * This value is 420000.
 */
#define PJMEDIA_AUDIODEV_ERRNO_START \
	    (PJ_ERRNO_START_USER + PJ_ERRNO_SPACE_SIZE*5)
#define PJMEDIA_AUDIODEV_ERRNO_END   \
	    (PJMEDIA_AUDIODEV_ERRNO_START + PJ_ERRNO_SPACE_SIZE - 1)


/**
 * Mapping from PortAudio error codes to pjmedia error space.
 */
#define PJMEDIA_AUDIODEV_PORTAUDIO_ERRNO_START \
	    (PJMEDIA_AUDIODEV_ERRNO_END-10000)
#define PJMEDIA_AUDIODEV_PORTAUDIO_ERRNO_END   \
	    (PJMEDIA_AUDIODEV_PORTAUDIO_ERRNO_START + 10000 -1)
/**
 * Convert PortAudio error code to PJLIB error code.
 * PortAudio error code range: 0 >= err >= -10000
 */
#define PJMEDIA_AUDIODEV_ERRNO_FROM_PORTAUDIO(err) \
	    ((int)PJMEDIA_AUDIODEV_PORTAUDIO_ERRNO_START-err)

/**
 * Mapping from Windows multimedia WaveIn error codes.
 */
#define PJMEDIA_AUDIODEV_WMME_IN_ERROR_START	\
	    (PJMEDIA_AUDIODEV_ERRNO_START + 30000)
#define PJMEDIA_AUDIODEV_WMME_IN_ERROR_END	\
	    (PJMEDIA_AUDIODEV_WMME_IN_ERROR_START + 1000 - 1)
/**
 * Convert WaveIn operation error codes to PJLIB error space.
 */
#define PJMEDIA_AUDIODEV_ERRNO_FROM_WMME_IN(err) \
	    ((int)PJMEDIA_AUDIODEV_WMME_IN_ERROR_START+err)


/**
 * Mapping from Windows multimedia WaveOut error codes.
 */
#define PJMEDIA_AUDIODEV_WMME_OUT_ERROR_START	\
	    (PJMEDIA_AUDIODEV_WMME_IN_ERROR_END + 1000)
#define PJMEDIA_AUDIODEV_WMME_OUT_ERROR_END	\
	    (PJMEDIA_AUDIODEV_WMME_OUT_ERROR_START + 1000)
/**
 * Convert WaveOut operation error codes to PJLIB error space.
 */
#define PJMEDIA_AUDIODEV_ERRNO_FROM_WMME_OUT(err) \
	    ((int)PJMEDIA_AUDIODEV_WMME_OUT_ERROR_START+err)


/**
 * Mapping from CoreAudio error codes to pjmedia error space.
 */
#define PJMEDIA_AUDIODEV_COREAUDIO_ERRNO_START \
	    (PJMEDIA_AUDIODEV_ERRNO_START+20000)
#define PJMEDIA_AUDIODEV_COREAUDIO_ERRNO_END   \
	    (PJMEDIA_AUDIODEV_COREAUDIO_ERRNO_START + 20000 -1)
/**
 * Convert CoreAudio error code to PJLIB error code.
 * CoreAudio error code range: 0 >= err >= -10000
 */
#define PJMEDIA_AUDIODEV_ERRNO_FROM_COREAUDIO(err) \
	    ((int)PJMEDIA_AUDIODEV_COREAUDIO_ERRNO_START-err)


/******************************PJMEDIA ERRNO*******************************/

/**
 * Start of error code relative to PJ_ERRNO_START_USER.
 */
#define PJMEDIA_ERRNO_START       (PJ_ERRNO_START_USER + PJ_ERRNO_SPACE_SIZE)
#define PJMEDIA_ERRNO_END         (PJMEDIA_ERRNO_START + PJ_ERRNO_SPACE_SIZE - 1)


/**
 * Mapping from PortAudio error codes to pjmedia error space.
 */
#define PJMEDIA_PORTAUDIO_ERRNO_START (PJMEDIA_ERRNO_END-10000)
#define PJMEDIA_PORTAUDIO_ERRNO_END   (PJMEDIA_PORTAUDIO_ERRNO_START + 10000 -1)
/**
 * Convert PortAudio error code to PJMEDIA error code.
 * PortAudio error code range: 0 >= err >= -10000
 */
#define PJMEDIA_ERRNO_FROM_PORTAUDIO(err)   ((int)PJMEDIA_PORTAUDIO_ERRNO_START-err)


#if defined(PJMEDIA_HAS_SRTP) && (PJMEDIA_HAS_SRTP != 0)

 /**
 * Mapping from LibSRTP error codes to pjmedia error space.
 */
#define PJMEDIA_LIBSRTP_ERRNO_START (PJMEDIA_ERRNO_END-10200)
#define PJMEDIA_LIBSRTP_ERRNO_END   (PJMEDIA_LIBSRTP_ERRNO_START + 200 - 1)
/**
 * Convert LibSRTP error code to PJMEDIA error code.
 * LibSRTP error code range: 0 <= err < 200
 */
#define PJMEDIA_ERRNO_FROM_LIBSRTP(err)   (PJMEDIA_LIBSRTP_ERRNO_START+err)

#endif

/************************************************************
 * GENERIC/GENERAL PJMEDIA ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * General/unknown PJMEDIA error.
 */
#define PJMEDIA_ERROR		    (PJMEDIA_ERRNO_START+1)	/* 220001 */


/************************************************************
 * SDP ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * Generic invalid SDP descriptor.
 */
#define PJMEDIA_SDP_EINSDP	    (PJMEDIA_ERRNO_START+20)    /* 220020 */
/**
 * @hideinitializer
 * Invalid SDP version.
 */
#define PJMEDIA_SDP_EINVER	    (PJMEDIA_ERRNO_START+21)    /* 220021 */
/**
 * @hideinitializer
 * Invalid SDP origin (o=) line.
 */
#define PJMEDIA_SDP_EINORIGIN	    (PJMEDIA_ERRNO_START+22)    /* 220022 */
/**
 * @hideinitializer
 * Invalid SDP time (t=) line.
 */
#define PJMEDIA_SDP_EINTIME	    (PJMEDIA_ERRNO_START+23)    /* 220023 */
/**
 * @hideinitializer
 * Empty SDP subject/name (s=) line.
 */
#define PJMEDIA_SDP_EINNAME	    (PJMEDIA_ERRNO_START+24)    /* 220024 */
/**
 * @hideinitializer
 * Invalid SDP connection info (c=) line.
 */
#define PJMEDIA_SDP_EINCONN	    (PJMEDIA_ERRNO_START+25)    /* 220025 */
/**
 * @hideinitializer
 * Missing SDP connection info line.
 */
#define PJMEDIA_SDP_EMISSINGCONN    (PJMEDIA_ERRNO_START+26)    /* 220026 */
/**
 * @hideinitializer
 * Invalid attribute (a=) line.
 */
#define PJMEDIA_SDP_EINATTR	    (PJMEDIA_ERRNO_START+27)    /* 220027 */
/**
 * @hideinitializer
 * Invalid rtpmap attribute.
 */
#define PJMEDIA_SDP_EINRTPMAP	    (PJMEDIA_ERRNO_START+28)    /* 220028 */
/**
 * @hideinitializer
 * rtpmap attribute is too long.
 */
#define PJMEDIA_SDP_ERTPMAPTOOLONG  (PJMEDIA_ERRNO_START+29)    /* 220029 */
/**
 * @hideinitializer
 * rtpmap is missing for dynamic payload type.
 */
#define PJMEDIA_SDP_EMISSINGRTPMAP  (PJMEDIA_ERRNO_START+30)    /* 220030 */
/**
 * @hideinitializer
 * Invalid SDP media (m=) line.
 */
#define PJMEDIA_SDP_EINMEDIA	    (PJMEDIA_ERRNO_START+31)    /* 220031 */
/**
 * @hideinitializer
 * No payload format in the media stream.
 */
#define PJMEDIA_SDP_ENOFMT	    (PJMEDIA_ERRNO_START+32)    /* 220032 */
/**
 * @hideinitializer
 * Invalid payload type in media.
 */
#define PJMEDIA_SDP_EINPT	    (PJMEDIA_ERRNO_START+33)    /* 220033 */
/**
 * @hideinitializer
 * Invalid SDP "fmtp" attribute.
 */
#define PJMEDIA_SDP_EINFMTP	    (PJMEDIA_ERRNO_START+34)    /* 220034 */
/**
 * @hideinitializer
 * Invalid SDP "rtcp" attribute.
 */
#define PJMEDIA_SDP_EINRTCP	    (PJMEDIA_ERRNO_START+35)    /* 220035 */
/**
 * @hideinitializer
 * Invalid SDP media transport protocol.
 */
#define PJMEDIA_SDP_EINPROTO	    (PJMEDIA_ERRNO_START+36)    /* 220036 */


/************************************************************
 * SDP NEGOTIATOR ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * Invalid state to perform the specified operation.
 */
#define PJMEDIA_SDPNEG_EINSTATE	    (PJMEDIA_ERRNO_START+40)    /* 220040 */
/**
 * @hideinitializer
 * No initial local SDP.
 */
#define PJMEDIA_SDPNEG_ENOINITIAL   (PJMEDIA_ERRNO_START+41)    /* 220041 */
/**
 * @hideinitializer
 * No currently active SDP.
 */
#define PJMEDIA_SDPNEG_ENOACTIVE    (PJMEDIA_ERRNO_START+42)    /* 220042 */
/**
 * @hideinitializer
 * No current offer or answer.
 */
#define PJMEDIA_SDPNEG_ENONEG	    (PJMEDIA_ERRNO_START+43)    /* 220043 */
/**
 * @hideinitializer
 * Media count mismatch in offer and answer.
 */
#define PJMEDIA_SDPNEG_EMISMEDIA    (PJMEDIA_ERRNO_START+44)    /* 220044 */
/**
 * @hideinitializer
 * Media type is different in the remote answer.
 */
#define PJMEDIA_SDPNEG_EINVANSMEDIA (PJMEDIA_ERRNO_START+45)    /* 220045 */
/**
 * @hideinitializer
 * Transport type is different in the remote answer.
 */
#define PJMEDIA_SDPNEG_EINVANSTP    (PJMEDIA_ERRNO_START+46)    /* 220046 */
/**
 * @hideinitializer
 * No common media payload is provided in the answer.
 */
#define PJMEDIA_SDPNEG_EANSNOMEDIA  (PJMEDIA_ERRNO_START+47)    /* 220047 */
/**
 * @hideinitializer
 * No media is active after negotiation.
 */
#define PJMEDIA_SDPNEG_ENOMEDIA	    (PJMEDIA_ERRNO_START+48)    /* 220048 */
/**
 * @hideinitializer
 * No suitable codec for remote offer.
 */
#define PJMEDIA_SDPNEG_NOANSCODEC   (PJMEDIA_ERRNO_START+49)    /* 220049 */
/**
 * @hideinitializer
 * No suitable telephone-event for remote offer.
 */
#define PJMEDIA_SDPNEG_NOANSTELEVENT (PJMEDIA_ERRNO_START+50)   /* 220050 */
/**
 * @hideinitializer
 * No suitable answer for unknown remote offer.
 */
#define PJMEDIA_SDPNEG_NOANSUNKNOWN (PJMEDIA_ERRNO_START+51)    /* 220051 */


/************************************************************
 * SDP COMPARISON STATUS
 ***********************************************************/
/**
 * @hideinitializer
 * SDP media stream not equal.
 */
#define PJMEDIA_SDP_EMEDIANOTEQUAL  (PJMEDIA_ERRNO_START+60)    /* 220060 */
/**
 * @hideinitializer
 * Port number in SDP media descriptor not equal.
 */
#define PJMEDIA_SDP_EPORTNOTEQUAL   (PJMEDIA_ERRNO_START+61)    /* 220061 */
/**
 * @hideinitializer
 * Transport in SDP media descriptor not equal.
 */
#define PJMEDIA_SDP_ETPORTNOTEQUAL  (PJMEDIA_ERRNO_START+62)    /* 220062 */
/**
 * @hideinitializer
 * Media format in SDP media descriptor not equal.
 */
#define PJMEDIA_SDP_EFORMATNOTEQUAL (PJMEDIA_ERRNO_START+63)    /* 220063 */
/**
 * @hideinitializer
 * SDP connection description not equal.
 */
#define PJMEDIA_SDP_ECONNNOTEQUAL   (PJMEDIA_ERRNO_START+64)    /* 220064 */
/**
 * @hideinitializer
 * SDP attributes not equal.
 */
#define PJMEDIA_SDP_EATTRNOTEQUAL   (PJMEDIA_ERRNO_START+65)    /* 220065 */
/**
 * @hideinitializer
 * SDP media direction not equal.
 */
#define PJMEDIA_SDP_EDIRNOTEQUAL    (PJMEDIA_ERRNO_START+66)    /* 220066 */
/**
 * @hideinitializer
 * SDP fmtp attribute not equal.
 */
#define PJMEDIA_SDP_EFMTPNOTEQUAL   (PJMEDIA_ERRNO_START+67)    /* 220067 */
/**
 * @hideinitializer
 * SDP ftpmap attribute not equal.
 */
#define PJMEDIA_SDP_ERTPMAPNOTEQUAL (PJMEDIA_ERRNO_START+68)    /* 220068 */
/**
 * @hideinitializer
 * SDP session descriptor not equal.
 */
#define PJMEDIA_SDP_ESESSNOTEQUAL   (PJMEDIA_ERRNO_START+69)    /* 220069 */
/**
 * @hideinitializer
 * SDP origin not equal.
 */
#define PJMEDIA_SDP_EORIGINNOTEQUAL (PJMEDIA_ERRNO_START+70)    /* 220070 */
/**
 * @hideinitializer
 * SDP name/subject not equal.
 */
#define PJMEDIA_SDP_ENAMENOTEQUAL   (PJMEDIA_ERRNO_START+71)    /* 220071 */
/**
 * @hideinitializer
 * SDP time not equal.
 */
#define PJMEDIA_SDP_ETIMENOTEQUAL   (PJMEDIA_ERRNO_START+72)    /* 220072 */


/************************************************************
 * CODEC
 ***********************************************************/
/**
 * @hideinitializer
 * Unsupported codec.
 */
#define PJMEDIA_CODEC_EUNSUP	    (PJMEDIA_ERRNO_START+80)    /* 220080 */
/**
 * @hideinitializer
 * Codec internal creation error.
 */
#define PJMEDIA_CODEC_EFAILED	    (PJMEDIA_ERRNO_START+81)    /* 220081 */
/**
 * @hideinitializer
 * Codec frame is too short.
 */
#define PJMEDIA_CODEC_EFRMTOOSHORT  (PJMEDIA_ERRNO_START+82)    /* 220082 */
/**
 * @hideinitializer
 * PCM buffer is too short.
 */
#define PJMEDIA_CODEC_EPCMTOOSHORT  (PJMEDIA_ERRNO_START+83)    /* 220083 */
/**
 * @hideinitializer
 * Invalid codec frame length.
 */
#define PJMEDIA_CODEC_EFRMINLEN	    (PJMEDIA_ERRNO_START+84)    /* 220084 */
/**
 * @hideinitializer
 * Invalid PCM frame length.
 */
#define PJMEDIA_CODEC_EPCMFRMINLEN  (PJMEDIA_ERRNO_START+85)    /* 220085 */
/**
 * @hideinitializer
 * Invalid mode.
 */
#define PJMEDIA_CODEC_EINMODE	    (PJMEDIA_ERRNO_START+86)    /* 220086 */


/************************************************************
 * MEDIA
 ***********************************************************/
/**
 * @hideinitializer
 * Invalid remote IP address (in SDP).
 */
#define PJMEDIA_EINVALIDIP	    (PJMEDIA_ERRNO_START+100)    /* 220100 */
/**
 * @hideinitializer
 * Asymetric codec is not supported.
 */
#define PJMEDIA_EASYMCODEC	    (PJMEDIA_ERRNO_START+101)    /* 220101 */
/**
 * @hideinitializer
 * Invalid payload type.
 */
#define PJMEDIA_EINVALIDPT	    (PJMEDIA_ERRNO_START+102)    /* 220102 */
/**
 * @hideinitializer
 * Missing rtpmap.
 */
#define PJMEDIA_EMISSINGRTPMAP	    (PJMEDIA_ERRNO_START+103)    /* 220103 */
/**
 * @hideinitializer
 * Invalid media type.
 */
#define PJMEDIA_EINVALIMEDIATYPE    (PJMEDIA_ERRNO_START+104)    /* 220104 */
/**
 * @hideinitializer
 * Remote does not support DTMF.
 */
#define PJMEDIA_EREMOTENODTMF	    (PJMEDIA_ERRNO_START+105)    /* 220105 */
/**
 * @hideinitializer
 * Invalid DTMF digit.
 */
#define PJMEDIA_RTP_EINDTMF	    (PJMEDIA_ERRNO_START+106)    /* 220106 */
/**
 * @hideinitializer
 * Remote does not support RFC 2833
 */
#define PJMEDIA_RTP_EREMNORFC2833   (PJMEDIA_ERRNO_START+107)    /* 220107 */



/************************************************************
 * RTP SESSION ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * General invalid RTP packet error.
 */
#define PJMEDIA_RTP_EINPKT	    (PJMEDIA_ERRNO_START+120)    /* 220120 */
/**
 * @hideinitializer
 * Invalid RTP packet packing.
 */
#define PJMEDIA_RTP_EINPACK	    (PJMEDIA_ERRNO_START+121)    /* 220121 */
/**
 * @hideinitializer
 * Invalid RTP packet version.
 */
#define PJMEDIA_RTP_EINVER	    (PJMEDIA_ERRNO_START+122)    /* 220122 */
/**
 * @hideinitializer
 * RTP SSRC id mismatch.
 */
#define PJMEDIA_RTP_EINSSRC	    (PJMEDIA_ERRNO_START+123)    /* 220123 */
/**
 * @hideinitializer
 * RTP payload type mismatch.
 */
#define PJMEDIA_RTP_EINPT	    (PJMEDIA_ERRNO_START+124)    /* 220124 */
/**
 * @hideinitializer
 * Invalid RTP packet length.
 */
#define PJMEDIA_RTP_EINLEN	    (PJMEDIA_ERRNO_START+125)    /* 220125 */
/**
 * @hideinitializer
 * RTP session restarted.
 */
#define PJMEDIA_RTP_ESESSRESTART    (PJMEDIA_ERRNO_START+130)    /* 220130 */
/**
 * @hideinitializer
 * RTP session in probation
 */
#define PJMEDIA_RTP_ESESSPROBATION  (PJMEDIA_ERRNO_START+131)    /* 220131 */
/**
 * @hideinitializer
 * Bad RTP sequence number
 */
#define PJMEDIA_RTP_EBADSEQ	    (PJMEDIA_ERRNO_START+132)    /* 220132 */
/**
 * @hideinitializer
 * RTP media port destination is not configured
 */
#define PJMEDIA_RTP_EBADDEST	    (PJMEDIA_ERRNO_START+133)    /* 220133 */
/**
 * @hideinitializer
 * RTP is not configured.
 */
#define PJMEDIA_RTP_ENOCONFIG	    (PJMEDIA_ERRNO_START+134)    /* 220134 */


/************************************************************
 * PORT ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * Generic incompatible port error.
 */
#define PJMEDIA_ENOTCOMPATIBLE	    (PJMEDIA_ERRNO_START+160)    /* 220160 */
/**
 * @hideinitializer
 * Incompatible clock rate
 */
#define PJMEDIA_ENCCLOCKRATE	    (PJMEDIA_ERRNO_START+161)    /* 220161 */
/**
 * @hideinitializer
 * Incompatible samples per frame
 */
#define PJMEDIA_ENCSAMPLESPFRAME    (PJMEDIA_ERRNO_START+162)    /* 220162 */
/**
 * @hideinitializer
 * Incompatible media type
 */
#define PJMEDIA_ENCTYPE		    (PJMEDIA_ERRNO_START+163)    /* 220163 */
/**
 * @hideinitializer
 * Incompatible bits per sample
 */
#define PJMEDIA_ENCBITS		    (PJMEDIA_ERRNO_START+164)    /* 220164 */
/**
 * @hideinitializer
 * Incompatible bytes per frame
 */
#define PJMEDIA_ENCBYTES	    (PJMEDIA_ERRNO_START+165)    /* 220165 */
/**
 * @hideinitializer
 * Incompatible number of channels
 */
#define PJMEDIA_ENCCHANNEL	    (PJMEDIA_ERRNO_START+166)    /* 220166 */


/************************************************************
 * FILE ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * Not a valid WAVE file.
 */
#define PJMEDIA_ENOTVALIDWAVE	    (PJMEDIA_ERRNO_START+180)    /* 220180 */
/**
 * @hideinitializer
 * Unsupported WAVE file.
 */
#define PJMEDIA_EWAVEUNSUPP	    (PJMEDIA_ERRNO_START+181)    /* 220181 */
/**
 * @hideinitializer
 * Wave file too short.
 */
#define PJMEDIA_EWAVETOOSHORT	    (PJMEDIA_ERRNO_START+182)    /* 220182 */
/**
 * @hideinitializer
 * Sound frame is too large for file buffer.
 */
#define PJMEDIA_EFRMFILETOOBIG	    (PJMEDIA_ERRNO_START+183)    /* 220183 */


/************************************************************
 * SOUND DEVICE ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * No suitable audio capture device.
 */
#define PJMEDIA_ENOSNDREC	    (PJMEDIA_ERRNO_START+200)    /* 220200 */
/**
 * @hideinitializer
 * No suitable audio playback device.
 */
#define PJMEDIA_ENOSNDPLAY	    (PJMEDIA_ERRNO_START+201)    /* 220201 */
/**
 * @hideinitializer
 * Invalid sound device ID.
 */
#define PJMEDIA_ESNDINDEVID	    (PJMEDIA_ERRNO_START+202)    /* 220202 */
/**
 * @hideinitializer
 * Invalid sample format for sound device.
 */
#define PJMEDIA_ESNDINSAMPLEFMT	    (PJMEDIA_ERRNO_START+203)    /* 220203 */


#if defined(PJMEDIA_HAS_SRTP) && (PJMEDIA_HAS_SRTP != 0)
/************************************************************
 * SRTP TRANSPORT ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * SRTP crypto-suite name not match the offerer tag.
 */
#define PJMEDIA_SRTP_ECRYPTONOTMATCH (PJMEDIA_ERRNO_START+220)   /* 220220 */
/**
 * @hideinitializer
 * Invalid SRTP key length for specific crypto.
 */
#define PJMEDIA_SRTP_EINKEYLEN	    (PJMEDIA_ERRNO_START+221)    /* 220221 */
/**
 * @hideinitializer
 * Unsupported SRTP crypto-suite.
 */
#define PJMEDIA_SRTP_ENOTSUPCRYPTO  (PJMEDIA_ERRNO_START+222)    /* 220222 */
/**
 * @hideinitializer
 * SRTP SDP contains ambigue answer.
 */
#define PJMEDIA_SRTP_ESDPAMBIGUEANS (PJMEDIA_ERRNO_START+223)    /* 220223 */
/**
 * @hideinitializer
 * Duplicated crypto tag.
 */
#define PJMEDIA_SRTP_ESDPDUPCRYPTOTAG (PJMEDIA_ERRNO_START+224)  /* 220224 */
/**
 * @hideinitializer
 * Invalid crypto attribute.
 */
#define PJMEDIA_SRTP_ESDPINCRYPTO   (PJMEDIA_ERRNO_START+225)    /* 220225 */
/**
 * @hideinitializer
 * Invalid crypto tag.
 */
#define PJMEDIA_SRTP_ESDPINCRYPTOTAG (PJMEDIA_ERRNO_START+226)   /* 220226 */
/**
 * @hideinitializer
 * Invalid SDP media transport for SRTP.
 */
#define PJMEDIA_SRTP_ESDPINTRANSPORT (PJMEDIA_ERRNO_START+227)   /* 220227 */
/**
 * @hideinitializer
 * SRTP crypto attribute required in SDP.
 */
#define PJMEDIA_SRTP_ESDPREQCRYPTO  (PJMEDIA_ERRNO_START+228)    /* 220228 */
/**
 * @hideinitializer
 * Secure transport required in SDP media descriptor.
 */
#define PJMEDIA_SRTP_ESDPREQSECTP   (PJMEDIA_ERRNO_START+229)    /* 220229 */

#endif /* PJMEDIA_HAS_SRTP */


/****************************PJSIP_SIMPLE ERRNO*******************************/
/**
 * Start of error code relative to PJ_ERRNO_START_USER.
 */
#define PJSIP_SIMPLE_ERRNO_START  (PJ_ERRNO_START_USER + PJ_ERRNO_SPACE_SIZE*2)


/************************************************************
 * EVENT PACKAGE ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * No event package with the specified name.
 */
#define PJSIP_SIMPLE_ENOPKG	    (PJSIP_SIMPLE_ERRNO_START+1)    /*270001*/
/**
 * @hideinitializer
 * Event package already exists.
 */
#define PJSIP_SIMPLE_EPKGEXISTS	    (PJSIP_SIMPLE_ERRNO_START+2)    /*270002*/


/************************************************************
 * PRESENCE ERROR
 ***********************************************************/
/**
 * @hideinitializer
 * Expecting SUBSCRIBE request
 */
#define PJSIP_SIMPLE_ENOTSUBSCRIBE  (PJSIP_SIMPLE_ERRNO_START+20)   /*270020*/
/**
 * @hideinitializer
 * No presence associated with subscription
 */
#define PJSIP_SIMPLE_ENOPRESENCE    (PJSIP_SIMPLE_ERRNO_START+21)   /*270021*/
/**
 * @hideinitializer
 * No presence info in server subscription
 */
#define PJSIP_SIMPLE_ENOPRESENCEINFO (PJSIP_SIMPLE_ERRNO_START+22)  /*270022*/
/**
 * @hideinitializer
 * Bad Content-Type
 */
#define PJSIP_SIMPLE_EBADCONTENT    (PJSIP_SIMPLE_ERRNO_START+23)   /*270023*/
/**
 * @hideinitializer
 * Bad PIDF Message
 */
#define PJSIP_SIMPLE_EBADPIDF	    (PJSIP_SIMPLE_ERRNO_START+24)   /*270024*/
/**
 * @hideinitializer
 * Bad XPIDF Message
 */
#define PJSIP_SIMPLE_EBADXPIDF	    (PJSIP_SIMPLE_ERRNO_START+25)   /*270025*/
/**
 * @hideinitializer
 * Bad RPID Message
 */
#define PJSIP_SIMPLE_EBADRPID	    (PJSIP_SIMPLE_ERRNO_START+26)   /*270026*/


/************************************************************
 * ISCOMPOSING ERRORS
 ***********************************************************/
/**
 * @hideinitializer
 * Bad isComposing XML message.
 */
#define PJSIP_SIMPLE_EBADISCOMPOSE  (PJSIP_SIMPLE_ERRNO_START+40)   /*270040*/


/******************************PJLIB_UTIL ERRNO*******************************/

/**
 * @defgroup PJLIB_UTIL_ERROR Error Codes
 * @ingroup PJLIB_UTIL_BASE
 * @{
 */

/**
 * Start of error code relative to PJ_ERRNO_START_USER.
 * This value is 320000.
 */
#define PJLIB_UTIL_ERRNO_START    (PJ_ERRNO_START_USER + PJ_ERRNO_SPACE_SIZE*3)


/************************************************************
 * STUN ERROR
 ***********************************************************/
/**
 * @hideinitializer
 * Unable to resolve STUN server
 */
#define PJLIB_UTIL_ESTUNRESOLVE	    (PJLIB_UTIL_ERRNO_START+1)	/* 320001 */
/**
 * @hideinitializer
 * Unknown STUN message type.
 */
#define PJLIB_UTIL_ESTUNINMSGTYPE   (PJLIB_UTIL_ERRNO_START+2)	/* 320002 */
/**
 * @hideinitializer
 * Invalid STUN message length
 */
#define PJLIB_UTIL_ESTUNINMSGLEN    (PJLIB_UTIL_ERRNO_START+3)	/* 320003 */
/**
 * @hideinitializer
 * Invalid STUN attribute length
 */
#define PJLIB_UTIL_ESTUNINATTRLEN   (PJLIB_UTIL_ERRNO_START+4)	/* 320004 */
/**
 * @hideinitializer
 * Invalid STUN attribute type
 */
#define PJLIB_UTIL_ESTUNINATTRTYPE  (PJLIB_UTIL_ERRNO_START+5)	/* 320005 */
/**
 * @hideinitializer
 * Invalid STUN server/socket index
 */
#define PJLIB_UTIL_ESTUNININDEX     (PJLIB_UTIL_ERRNO_START+6)	/* 320006 */
/**
 * @hideinitializer
 * No STUN binding response in the message
 */
#define PJLIB_UTIL_ESTUNNOBINDRES   (PJLIB_UTIL_ERRNO_START+7)	/* 320007 */
/**
 * @hideinitializer
 * Received STUN error attribute
 */
#define PJLIB_UTIL_ESTUNRECVERRATTR (PJLIB_UTIL_ERRNO_START+8)	/* 320008 */
/**
 * @hideinitializer
 * No STUN mapped address attribute
 */
#define PJLIB_UTIL_ESTUNNOMAP       (PJLIB_UTIL_ERRNO_START+9)	/* 320009 */
/**
 * @hideinitializer
 * Received no response from STUN server
 */
#define PJLIB_UTIL_ESTUNNOTRESPOND  (PJLIB_UTIL_ERRNO_START+10)	/* 320010 */
/**
 * @hideinitializer
 * Symetric NAT detected by STUN
 */
#define PJLIB_UTIL_ESTUNSYMMETRIC   (PJLIB_UTIL_ERRNO_START+11)	/* 320011 */
/**
 * @hideinitializer
 * Invalid STUN magic value
 */
#define PJLIB_UTIL_ESTUNNOTMAGIC    (PJLIB_UTIL_ERRNO_START+12)	/* 320012 */
/**
 * @hideinitializer
 * Invalid STUN fingerprint value
 */
#define PJLIB_UTIL_ESTUNFINGERPRINT (PJLIB_UTIL_ERRNO_START+13)	/* 320013 */



/************************************************************
 * XML ERROR
 ***********************************************************/
/**
 * @hideinitializer
 * General invalid XML message.
 */
#define PJLIB_UTIL_EINXML	    (PJLIB_UTIL_ERRNO_START+20)	/* 320020 */



/************************************************************
 * DNS ERROR
 ***********************************************************/
/**
 * @hideinitializer
 * DNS query packet buffer is too small.
 * This error occurs when the user supplied buffer for creating DNS
 * query (#pj_dns_make_query() function) is too small.
 */
#define PJLIB_UTIL_EDNSQRYTOOSMALL  (PJLIB_UTIL_ERRNO_START+40)	/* 320040 */
/**
 * @hideinitializer
 * Invalid DNS packet length.
 * This error occurs when the received DNS response packet does not
 * match all the fields length.
 */
#define PJLIB_UTIL_EDNSINSIZE	    (PJLIB_UTIL_ERRNO_START+41)	/* 320041 */
/**
 * @hideinitializer
 * Invalid DNS class.
 * This error occurs when the received DNS response contains network
 * class other than IN (Internet).
 */
#define PJLIB_UTIL_EDNSINCLASS	    (PJLIB_UTIL_ERRNO_START+42)	/* 320042 */
/**
 * @hideinitializer
 * Invalid DNS name pointer.
 * This error occurs when parsing the compressed names inside DNS
 * response packet, when the name pointer points to an invalid address
 * or the parsing has triggerred too much recursion.
 */
#define PJLIB_UTIL_EDNSINNAMEPTR    (PJLIB_UTIL_ERRNO_START+43)	/* 320043 */
/**
 * @hideinitializer
 * Invalid DNS nameserver address. If hostname was specified for nameserver
 * address, this error means that the function was unable to resolve
 * the nameserver hostname.
 */
#define PJLIB_UTIL_EDNSINNSADDR	    (PJLIB_UTIL_ERRNO_START+44)	/* 320044 */
/**
 * @hideinitializer
 * No nameserver is in DNS resolver. No nameserver is configured in the 
 * resolver.
 */
#define PJLIB_UTIL_EDNSNONS	    (PJLIB_UTIL_ERRNO_START+45)	/* 320045 */
/**
 * @hideinitializer
 * No working DNS nameserver. All nameservers have been queried,
 * but none was able to serve any DNS requests. These "bad" nameservers
 * will be re-tested again for "goodness" after some period.
 */
#define PJLIB_UTIL_EDNSNOWORKINGNS  (PJLIB_UTIL_ERRNO_START+46)	/* 320046 */
/**
 * @hideinitializer
 * No answer record in the DNS response.
 */
#define PJLIB_UTIL_EDNSNOANSWERREC  (PJLIB_UTIL_ERRNO_START+47)	/* 320047 */
/**
 * @hideinitializer
 * Invalid DNS answer. This error is raised for example when the DNS
 * answer does not have a query section, or the type of RR in the answer
 * doesn't match the query.
 */
#define PJLIB_UTIL_EDNSINANSWER	    (PJLIB_UTIL_ERRNO_START+48)	/* 320048 */


/* DNS ERRORS MAPPED FROM RCODE: */

/**
 * Start of error code mapped from DNS RCODE
 */
#define PJLIB_UTIL_DNS_RCODE_START  (PJLIB_UTIL_ERRNO_START+50)	/* 320050 */

/**
 * Map DNS RCODE status into pj_status_t.
 */
#define PJ_STATUS_FROM_DNS_RCODE(rcode)	(rcode==0 ? PJ_SUCCESS : \
					 PJLIB_UTIL_DNS_RCODE_START+rcode)
/**
 * @hideinitializer
 * Format error - The name server was unable to interpret the query.
 * This corresponds to DNS RCODE 1.
 */
#define PJLIB_UTIL_EDNS_FORMERR	    PJ_STATUS_FROM_DNS_RCODE(1)	/* 320051 */
/**
 * @hideinitializer
 * Server failure - The name server was unable to process this query due to a
 * problem with the name server.
 * This corresponds to DNS RCODE 2.
 */
#define PJLIB_UTIL_EDNS_SERVFAIL    PJ_STATUS_FROM_DNS_RCODE(2)	/* 320052 */
/**
 * @hideinitializer
 * Name Error - Meaningful only for responses from an authoritative name
 * server, this code signifies that the domain name referenced in the query 
 * does not exist.
 * This corresponds to DNS RCODE 3.
 */
#define PJLIB_UTIL_EDNS_NXDOMAIN    PJ_STATUS_FROM_DNS_RCODE(3)	/* 320053 */
/**
 * @hideinitializer
 * Not Implemented - The name server does not support the requested kind of 
 * query.
 * This corresponds to DNS RCODE 4.
 */
#define PJLIB_UTIL_EDNS_NOTIMPL    PJ_STATUS_FROM_DNS_RCODE(4)	/* 320054 */
/**
 * @hideinitializer
 * Refused - The name server refuses to perform the specified operation for
 * policy reasons.
 * This corresponds to DNS RCODE 5.
 */
#define PJLIB_UTIL_EDNS_REFUSED	    PJ_STATUS_FROM_DNS_RCODE(5)	/* 320055 */
/**
 * @hideinitializer
 * The name exists.
 * This corresponds to DNS RCODE 6.
 */
#define PJLIB_UTIL_EDNS_YXDOMAIN    PJ_STATUS_FROM_DNS_RCODE(6)	/* 320056 */
/**
 * @hideinitializer
 * The RRset (name, type) exists.
 * This corresponds to DNS RCODE 7.
 */
#define PJLIB_UTIL_EDNS_YXRRSET	    PJ_STATUS_FROM_DNS_RCODE(7)	/* 320057 */
/**
 * @hideinitializer
 * The RRset (name, type) does not exist.
 * This corresponds to DNS RCODE 8.
 */
#define PJLIB_UTIL_EDNS_NXRRSET	    PJ_STATUS_FROM_DNS_RCODE(8)	/* 320058 */
/**
 * @hideinitializer
 * The requestor is not authorized to perform this operation.
 * This corresponds to DNS RCODE 9.
 */
#define PJLIB_UTIL_EDNS_NOTAUTH	    PJ_STATUS_FROM_DNS_RCODE(9)	/* 320059 */
/**
 * @hideinitializer
 * The zone specified is not a zone.
 * This corresponds to DNS RCODE 10.
 */
#define PJLIB_UTIL_EDNS_NOTZONE	    PJ_STATUS_FROM_DNS_RCODE(10)/* 320060 */


/************************************************************
 * NEW STUN ERROR
 ***********************************************************/
/* Messaging errors */
/**
 * @hideinitializer
 * Too many STUN attributes.
 */
#define PJLIB_UTIL_ESTUNTOOMANYATTR (PJLIB_UTIL_ERRNO_START+110)/* 320110 */
/**
 * @hideinitializer
 * Unknown STUN attribute. This error happens when the decoder encounters
 * mandatory attribute type which it doesn't understand.
 */
#define PJLIB_UTIL_ESTUNUNKNOWNATTR (PJLIB_UTIL_ERRNO_START+111)/* 320111 */
/**
 * @hideinitializer
 * Invalid STUN socket address length.
 */
#define PJLIB_UTIL_ESTUNINADDRLEN   (PJLIB_UTIL_ERRNO_START+112)/* 320112 */
/**
 * @hideinitializer
 * STUN IPv6 attribute not supported
 */
#define PJLIB_UTIL_ESTUNIPV6NOTSUPP (PJLIB_UTIL_ERRNO_START+113)/* 320113 */
/**
 * @hideinitializer
 * Expecting STUN response message.
 */
#define PJLIB_UTIL_ESTUNNOTRESPONSE (PJLIB_UTIL_ERRNO_START+114)/* 320114 */
/**
 * @hideinitializer
 * STUN transaction ID mismatch.
 */
#define PJLIB_UTIL_ESTUNINVALIDID   (PJLIB_UTIL_ERRNO_START+115)/* 320115 */
/**
 * @hideinitializer
 * Unable to find handler for the request.
 */
#define PJLIB_UTIL_ESTUNNOHANDLER   (PJLIB_UTIL_ERRNO_START+116)/* 320116 */
/**
 * @hideinitializer
 * Found non-FINGERPRINT attribute after MESSAGE-INTEGRITY. This is not
 * valid since MESSAGE-INTEGRITY MUST be the last attribute or the
 * attribute right before FINGERPRINT before the message.
 */
#define PJLIB_UTIL_ESTUNMSGINTPOS    (PJLIB_UTIL_ERRNO_START+118)/* 320118 */
/**
 * @hideinitializer
 * Found attribute after FINGERPRINT. This is not valid since FINGERPRINT
 * MUST be the last attribute in the message.
 */
#define PJLIB_UTIL_ESTUNFINGERPOS   (PJLIB_UTIL_ERRNO_START+119)/* 320119 */
/**
 * @hideinitializer
 * Missing STUN USERNAME attribute.
 * When credential is included in the STUN message (MESSAGE-INTEGRITY is
 * present), the USERNAME attribute must be present in the message.
 */
#define PJLIB_UTIL_ESTUNNOUSERNAME  (PJLIB_UTIL_ERRNO_START+120)/* 320120 */
/**
 * @hideinitializer
 * Unknown STUN username/credential.
 */
#define PJLIB_UTIL_ESTUNUSERNAME    (PJLIB_UTIL_ERRNO_START+121)/* 320121 */
/**
 * @hideinitializer
 * Missing/invalidSTUN MESSAGE-INTEGRITY attribute.
 */
#define PJLIB_UTIL_ESTUNMSGINT	    (PJLIB_UTIL_ERRNO_START+122)/* 320122 */
/**
 * @hideinitializer
 * Found duplicate STUN attribute.
 */
#define PJLIB_UTIL_ESTUNDUPATTR	    (PJLIB_UTIL_ERRNO_START+123)/* 320123 */
/**
 * @hideinitializer
 * Missing STUN REALM attribute.
 */
#define PJLIB_UTIL_ESTUNNOREALM	    (PJLIB_UTIL_ERRNO_START+124)/* 320124 */
/**
 * @hideinitializer
 * Missing/stale STUN NONCE attribute value.
 */
#define PJLIB_UTIL_ESTUNNONCE	    (PJLIB_UTIL_ERRNO_START+125)/* 320125 */
/**
 * @hideinitializer
 * STUN transaction terminates with failure.
 */
#define PJLIB_UTIL_ESTUNTSXFAILED    (PJLIB_UTIL_ERRNO_START+126)/* 320126 */


//#define PJ_STATUS_FROM_STUN_CODE(code)	(PJLIB_UTIL_ERRNO_START+code)

/************************************************************
 * HTTP Client ERROR
 ***********************************************************/
/**
 * @hideinitializer
 * Invalid URL format
 */
#define PJLIB_UTIL_EHTTPINURL	    (PJLIB_UTIL_ERRNO_START+151)/* 320151 */
/**
 * @hideinitializer
 * Invalid port number
 */
#define PJLIB_UTIL_EHTTPINPORT	    (PJLIB_UTIL_ERRNO_START+152)/* 320152 */
/**
 * @hideinitializer
 * Incomplete headers received
 */
#define PJLIB_UTIL_EHTTPINCHDR	    (PJLIB_UTIL_ERRNO_START+153)/* 320153 */
/**
 * @hideinitializer
 * Insufficient buffer
 */
#define PJLIB_UTIL_EHTTPINSBUF	    (PJLIB_UTIL_ERRNO_START+154)/* 320154 */
/**
 * @hideinitializer
 * Connection lost
 */
#define PJLIB_UTIL_EHTTPLOST	    (PJLIB_UTIL_ERRNO_START+155)/* 320155 */



/******************************PJNATH ERRNO*******************************/

/**
 * @defgroup PJNATH_ERROR NAT Helper Library Error Codes
 * @brief PJNATH specific error code constants
 * @ingroup PJNATH_STUN_BASE
 * @{
 */

/**
 * Start of error code relative to PJ_ERRNO_START_USER.
 * This value is 370000.
 */
#define PJNATH_ERRNO_START    (PJ_ERRNO_START_USER + PJ_ERRNO_SPACE_SIZE*4)


/************************************************************
 * STUN MESSAGING ERRORS
 ***********************************************************/

/**
 * Map STUN error code (300-699) into pj_status_t error space.
 */
#define PJ_STATUS_FROM_STUN_CODE(code)	(PJNATH_ERRNO_START+code)

/**
 * @hideinitializer
 * Invalid STUN message
 */
#define PJNATH_EINSTUNMSG	    (PJNATH_ERRNO_START+1)  /* 370001 */
/**
 * @hideinitializer
 * Invalid STUN message length.
 */
#define PJNATH_EINSTUNMSGLEN	    (PJNATH_ERRNO_START+2)  /* 370002 */
/**
 * @hideinitializer
 * Invalid or unexpected STUN message type
 */
#define	PJNATH_EINSTUNMSGTYPE	    (PJNATH_ERRNO_START+3)  /* 370003 */
/**
 * @hideinitializer
 * STUN transaction has timed out
 */
#define PJNATH_ESTUNTIMEDOUT	    (PJNATH_ERRNO_START+4)  /* 370004 */


/**
 * @hideinitializer
 * Too many STUN attributes.
 */
#define PJNATH_ESTUNTOOMANYATTR	    (PJNATH_ERRNO_START+21) /* 370021 */
/**
 * @hideinitializer
 * Invalid STUN attribute length.
 */
#define PJNATH_ESTUNINATTRLEN	    (PJNATH_ERRNO_START+22) /* 370022 */
/**
 * @hideinitializer
 * Found duplicate STUN attribute.
 */
#define PJNATH_ESTUNDUPATTR	    (PJNATH_ERRNO_START+23) /* 370023 */

/**
 * @hideinitializer
 * STUN FINGERPRINT verification failed
 */
#define PJNATH_ESTUNFINGERPRINT	    (PJNATH_ERRNO_START+30) /* 370030 */
/**
 * @hideinitializer
 * Invalid STUN attribute after MESSAGE-INTEGRITY.
 */
#define PJNATH_ESTUNMSGINTPOS	    (PJNATH_ERRNO_START+31) /* 370031 */
/**
 * @hideinitializer
 * Invalid STUN attribute after FINGERPRINT.
 */
#define PJNATH_ESTUNFINGERPOS	    (PJNATH_ERRNO_START+33) /* 370033 */


/**
 * @hideinitializer
 * STUN (XOR-)MAPPED-ADDRESS attribute not found
 */
#define PJNATH_ESTUNNOMAPPEDADDR    (PJNATH_ERRNO_START+40) /* 370040 */
/**
 * @hideinitializer
 * STUN IPv6 attribute not supported
 */
#define PJNATH_ESTUNIPV6NOTSUPP	    (PJNATH_ERRNO_START+41) /* 370041 */
/**
 * @hideinitializer
 * Invalid address family value in STUN message.
 */
#define PJNATH_EINVAF		    (PJNATH_ERRNO_START+42) /* 370042 */

/**
 * @hideinitializer
 * Invalid STUN server or server not configured.
 */
#define PJNATH_ESTUNINSERVER	    (PJNATH_ERRNO_START+50) /* 370050 */


/************************************************************
 * STUN SESSION/TRANSPORT ERROR CODES
 ***********************************************************/
/**
 * @hideinitializer
 * STUN object has been destoyed.
 */
#define PJNATH_ESTUNDESTROYED	    (PJNATH_ERRNO_START+60) /* 370060 */


/************************************************************
 * ICE ERROR CODES
 ***********************************************************/

/**
 * @hideinitializer
 * ICE session not available
 */
#define PJNATH_ENOICE		    (PJNATH_ERRNO_START+80) /* 370080 */
/**
 * @hideinitializer
 * ICE check is in progress
 */
#define PJNATH_EICEINPROGRESS	    (PJNATH_ERRNO_START+81) /* 370081 */
/**
 * @hideinitializer
 * This error indicates that ICE connectivity check has failed, because
 * there is at least one ICE component that does not have a valid check.
 * Normally this happens because the network topology had caused the
 * connectivity check to fail (e.g. no route between the two agents),
 * however other reasons may include software incompatibility between
 * the two agents, or incomplete candidates gathered by the agent(s).
 */
#define PJNATH_EICEFAILED	    (PJNATH_ERRNO_START+82) /* 370082 */
/**
 * @hideinitializer
 * Default destination does not match any ICE candidates
 */
#define PJNATH_EICEMISMATCH	    (PJNATH_ERRNO_START+83) /* 370083 */
/**
 * @hideinitializer
 * Invalid ICE component ID
 */
#define PJNATH_EICEINCOMPID	    (PJNATH_ERRNO_START+86) /* 370086 */
/**
 * @hideinitializer
 * Invalid ICE candidate ID
 */
#define PJNATH_EICEINCANDID	    (PJNATH_ERRNO_START+87) /* 370087 */
/**
 * @hideinitializer
 * Source address mismatch. This error occurs if the source address
 * of the response for ICE connectivity check is different than
 * the destination address of the request.
 */
#define PJNATH_EICEINSRCADDR	    (PJNATH_ERRNO_START+88) /* 370088 */
/**
 * @hideinitializer
 * Missing ICE SDP attribute
 */
#define PJNATH_EICEMISSINGSDP	    (PJNATH_ERRNO_START+90) /* 370090 */
/**
 * @hideinitializer
 * Invalid SDP "candidate" attribute
 */
#define PJNATH_EICEINCANDSDP	    (PJNATH_ERRNO_START+91) /* 370091 */
/**
 * @hideinitializer
 * No host candidate associated with srflx. This error occurs when
 * a server reflexive candidate is added without the matching 
 * host candidate.
 */
#define PJNATH_EICENOHOSTCAND	    (PJNATH_ERRNO_START+92) /* 370092 */
/**
 * @hideinitializer
 * Controlled agent timed-out in waiting for the controlling agent to 
 * send nominated check after all connectivity checks have completed.
 */
#define PJNATH_EICENOMTIMEOUT	    (PJNATH_ERRNO_START+93) /* 370093 */

/************************************************************
 * TURN ERROR CODES
 ***********************************************************/
/**
 * @hideinitializer
 * Invalid or unsupported TURN transport.
 */
#define PJNATH_ETURNINTP	    (PJNATH_ERRNO_START+120) /* 370120 */


/***************************PJMEDIA_AUDIODEV ERRNO**************************/

/************************************************************
 * Audio Device API error codes
 ***********************************************************/
/**
 * @hideinitializer
 * General/unknown error.
 */
#define PJMEDIA_EAUD_ERR	(PJMEDIA_AUDIODEV_ERRNO_START+1) /* 420001 */

/**
 * @hideinitializer
 * Unknown error from audio driver
 */
#define PJMEDIA_EAUD_SYSERR	(PJMEDIA_AUDIODEV_ERRNO_START+2) /* 420002 */

/**
 * @hideinitializer
 * Audio subsystem not initialized
 */
#define PJMEDIA_EAUD_INIT	(PJMEDIA_AUDIODEV_ERRNO_START+3) /* 420003 */

/**
 * @hideinitializer
 * Invalid audio device
 */
#define PJMEDIA_EAUD_INVDEV	(PJMEDIA_AUDIODEV_ERRNO_START+4) /* 420004 */

/**
 * @hideinitializer
 * Found no devices
 */
#define PJMEDIA_EAUD_NODEV	(PJMEDIA_AUDIODEV_ERRNO_START+5) /* 420005 */

/**
 * @hideinitializer
 * Unable to find default device
 */
#define PJMEDIA_EAUD_NODEFDEV	(PJMEDIA_AUDIODEV_ERRNO_START+6) /* 420006 */

/**
 * @hideinitializer
 * Device not ready
 */
#define PJMEDIA_EAUD_NOTREADY	(PJMEDIA_AUDIODEV_ERRNO_START+7) /* 420007 */

/**
 * @hideinitializer
 * The audio capability is invalid or not supported
 */
#define PJMEDIA_EAUD_INVCAP	(PJMEDIA_AUDIODEV_ERRNO_START+8) /* 420008 */

/**
 * @hideinitializer
 * The operation is invalid or not supported
 */
#define PJMEDIA_EAUD_INVOP	(PJMEDIA_AUDIODEV_ERRNO_START+9) /* 420009 */

/**
 * @hideinitializer
 * Bad or invalid audio device format
 */
#define PJMEDIA_EAUD_BADFORMAT	(PJMEDIA_AUDIODEV_ERRNO_START+10) /* 4200010 */

/**
 * @hideinitializer
 * Invalid audio device sample format
 */
#define PJMEDIA_EAUD_SAMPFORMAT	(PJMEDIA_AUDIODEV_ERRNO_START+11) /* 4200011 */

/**
 * @hideinitializer
 * Bad latency setting
 */
#define PJMEDIA_EAUD_BADLATENCY	(PJMEDIA_AUDIODEV_ERRNO_START+12) /* 4200012 */


#endif	/* __ERRNO_H__ */