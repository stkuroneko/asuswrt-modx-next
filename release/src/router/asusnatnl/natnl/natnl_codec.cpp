/* $Id: natnl_codec.c,v 1.1.1.1 2011/12/27 06:17:38 andrew Exp $ */
/* 
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */
/* This file contains file from Sun Microsystems, Inc, with the complete 
 * notice in the second half of this file.
 */
#include <natnl_codec.h>
#include <pjmedia/codec.h>
#include <pjmedia/endpoint.h>
#include <pjmedia/errno.h>
#include <pjmedia/port.h>
#include <pjmedia/plc.h>
#include <pjmedia/silencedet.h>
#include <pj/pool.h>
#include <pj/string.h>
#include <pj/assert.h>
#include <pjsua-lib/pjsua.h>

/*pjsip logging*/
#include <pj/log.h>

#define THIS_FILE "natnl_codec.c"

#define PJMEDIA_RTP_PT_NTC 126

#define NTC_BPS            64000
#define NTC_CODEC_CNT            0        /* number of codec to preallocate in memory */
#define PTIME                    10        /* basic frame size is 10 msec            */
#define FRAME_SIZE            (8000 * PTIME / 1000)   /* 80 bytes            */
#define SAMPLES_PER_FRAME   (8000 * PTIME / 1000)   /* 80 samples   */

/* Prototypes for NAT tunnel codec factory */
static pj_status_t ntc_test_alloc( pjmedia_codec_factory *factory, 
                                    const pjmedia_codec_info *id );
static pj_status_t ntc_default_attr( pjmedia_codec_factory *factory, 
                                      const pjmedia_codec_info *id, 
                                      pjmedia_codec_param *attr );
static pj_status_t ntc_enum_codecs (pjmedia_codec_factory *factory, 
                                     unsigned *count, 
                                     pjmedia_codec_info codecs[]);
static pj_status_t ntc_alloc_codec( pjmedia_codec_factory *factory, 
                                     const pjmedia_codec_info *id, 
                                     pjmedia_codec **p_codec);
static pj_status_t ntc_dealloc_codec( pjmedia_codec_factory *factory, 
                                       pjmedia_codec *codec );

/* Prototypes for NTC implementation. */
static pj_status_t  ntc_init( pjmedia_codec *codec, 
                               pj_pool_t *pool );
static pj_status_t  ntc_open( pjmedia_codec *codec, 
                               pjmedia_codec_param *attr );
static pj_status_t  ntc_close( pjmedia_codec *codec );
static pj_status_t  ntc_modify(pjmedia_codec *codec, 
                                const pjmedia_codec_param *attr );
static pj_status_t  ntc_parse(pjmedia_codec *codec,
                               void *pkt,
                               pj_size_t pkt_size,
                               const pj_timestamp *timestamp,
                               unsigned *frame_cnt,
                               pjmedia_frame frames[]);
static pj_status_t  ntc_encode( pjmedia_codec *codec, 
                                 const struct pjmedia_frame *input,
                                 unsigned output_buf_len, 
                                 struct pjmedia_frame *output);
static pj_status_t  ntc_decode( pjmedia_codec *codec, 
                                 const struct pjmedia_frame *input,
                                 unsigned output_buf_len, 
                                 struct pjmedia_frame *output);

/* Definition for NTC codec operations. */
static pjmedia_codec_op ntc_op = 
{
    &ntc_init,
    &ntc_open,
    &ntc_close,
    &ntc_modify,
    &ntc_parse,
    &ntc_encode,
    &ntc_decode,
    NULL
};

/* Definition for NTC codec factory operations. */
static pjmedia_codec_factory_op ntc_factory_op =
{
    &ntc_test_alloc,
    &ntc_default_attr,
    &ntc_enum_codecs,
    &ntc_alloc_codec,
    &ntc_dealloc_codec
};

/* NTC factory private data */
static struct ntc_factory
{
    pjmedia_codec_factory        base;
    pjmedia_endpt               *endpt;
    pj_pool_t                   *pool;
    pj_mutex_t                  *mutex;
    pjmedia_codec                codec_list;
} ntc_factory[PJSUA_MAX_INSTANCES];

/* NTC codec private data. */
struct ntc_private
{
    unsigned             pt;
    pj_bool_t            vad_enabled;
    pjmedia_silence_det *vad;
    pj_timestamp         last_tx;
};


PJ_DEF(pj_status_t) pjmedia_codec_ntc_init(int inst_id, pjmedia_endpt *endpt)
{
	PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_init() entered."));
    pjmedia_codec_mgr *codec_mgr;
    pj_status_t status;

    if (ntc_factory[inst_id].endpt != NULL) {
		/* Already initialized. */
		PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_init() leaving. status=[%d]", PJ_SUCCESS));
        return PJ_SUCCESS;
    }

    /* Init factory */
    ntc_factory[inst_id].base.op = &ntc_factory_op;
    ntc_factory[inst_id].base.factory_data = endpt;
    ntc_factory[inst_id].endpt = endpt;

    pj_list_init(&ntc_factory[inst_id].codec_list);

    /* Create pool */
    ntc_factory[inst_id].pool = pjmedia_endpt_create_pool(endpt, "ntc", 4000, 4000);
	if (!ntc_factory[inst_id].pool) {
		PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_init() leaving. status=[%d]", PJ_ENOMEM));
        return PJ_ENOMEM;
	}

    /* Create mutex. */
    status = pj_mutex_create_simple(ntc_factory[inst_id].pool, "ntc", 
                                    &ntc_factory[inst_id].mutex);
    if (status != PJ_SUCCESS)
        goto on_error;

    /* Get the codec manager. */
    codec_mgr = pjmedia_endpt_get_codec_mgr(endpt);
	if (!codec_mgr) {
		PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_init() leaving. status=[%d]", PJ_EINVALIDOP));
        return PJ_EINVALIDOP;
    }

    /* Register codec factory to endpoint. */
    status = pjmedia_codec_mgr_register_factory(codec_mgr, 
                                                &ntc_factory[inst_id].base);
	if (status != PJ_SUCCESS) {
		PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_init() leaving. status=[%d]", status));
        return status;
	}


	PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_init() leaving. status=[%d]", PJ_SUCCESS));
    return PJ_SUCCESS;

on_error:
    if (ntc_factory[inst_id].mutex) {
        pj_mutex_destroy(ntc_factory[inst_id].mutex);
        ntc_factory[inst_id].mutex = NULL;
    }
    if (ntc_factory[inst_id].pool) {
        pj_pool_release(ntc_factory[inst_id].pool);
        ntc_factory[inst_id].pool = NULL;
	}
	PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_init() leaving. status=[%d]", status));
    return status;
}

PJ_DEF(pj_status_t) pjmedia_codec_ntc_deinit(int inst_id)
{
	PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_deinit() entered."));
    pjmedia_codec_mgr *codec_mgr;
    pj_status_t status;

	if (ntc_factory[inst_id].endpt == NULL) {
		PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_deinit() leaving. staus=[%d]", PJ_SUCCESS));
        /* Not registered. */
        return PJ_SUCCESS;
    }

    /* Lock mutex. */
    pj_mutex_lock(ntc_factory[inst_id].mutex);

    /* Get the codec manager. */
    codec_mgr = pjmedia_endpt_get_codec_mgr(ntc_factory[inst_id].endpt);
    if (!codec_mgr) {
        ntc_factory[inst_id].endpt = NULL;
        pj_mutex_unlock(ntc_factory[inst_id].mutex);
        return PJ_EINVALIDOP;
    }

    /* Unregister NTC codec factory. */
    status = pjmedia_codec_mgr_unregister_factory(codec_mgr,
                                                  &ntc_factory[inst_id].base);
    ntc_factory[inst_id].endpt = NULL;

    /* Destroy mutex. */
    pj_mutex_destroy(ntc_factory[inst_id].mutex);
    ntc_factory[inst_id].mutex = NULL;


    /* Release pool. */
    pj_pool_release(ntc_factory[inst_id].pool);
    ntc_factory[inst_id].pool = NULL;

	PJ_LOG(5, (THIS_FILE, "pjmedia_codec_ntc_deinit() leaving. staus=[%d]", status));
    return status;
}

static pj_status_t ntc_test_alloc(pjmedia_codec_factory *factory, 
                                   const pjmedia_codec_info *id )
{
	PJ_LOG(5, (THIS_FILE, "ntc_test_alloc() entered."));
    PJ_UNUSED_ARG(factory);

    /* It's sufficient to check payload type only. */
	PJ_LOG(5, (THIS_FILE, "ntc_test_alloc() leaving."));
    return (id->pt == PJMEDIA_RTP_PT_NTC) ? 0:-1;
}

static pj_status_t ntc_default_attr (pjmedia_codec_factory *factory, 
                                      const pjmedia_codec_info *id, 
                                      pjmedia_codec_param *attr )
{
	PJ_LOG(5, (THIS_FILE, "ntc_default_attr() entered."));
    PJ_UNUSED_ARG(factory);

    pj_bzero(attr, sizeof(pjmedia_codec_param));
    attr->info.clock_rate = 8000;
    attr->info.channel_cnt = 1;
    attr->info.avg_bps = NTC_BPS;
    attr->info.max_bps = NTC_BPS;
    attr->info.pcm_bits_per_sample = 16;
    attr->info.frm_ptime = PTIME;
    attr->info.pt = (pj_uint8_t)id->pt;

    /* Set default frames per packet to 2 (or 20ms) */
    attr->setting.frm_per_pkt = 2;

    /* Enable VAD by default. */
    attr->setting.vad = 1;

    attr->setting.dec_fmtp.cnt = 1;
    attr->setting.dec_fmtp.param[0].name = pj_str("mode");
	attr->setting.dec_fmtp.param[0].val = pj_str("30");

	PJ_LOG(5, (THIS_FILE, "ntc_default_attr() leaving."));

    /* Default all other flag bits disabled. */

    return PJ_SUCCESS;
}

static pj_status_t ntc_enum_codecs(pjmedia_codec_factory *factory, 
                                    unsigned *count, 
                                    pjmedia_codec_info codecs[])
{

	PJ_LOG(5, (THIS_FILE, "ntc_enum_codecs() entered."));
    PJ_UNUSED_ARG(factory);
    PJ_ASSERT_RETURN(codecs && *count > 0, PJ_EINVAL);

    pj_bzero(&codecs[0], sizeof(pjmedia_codec_info));
    codecs[0].encoding_name = pj_str("NTC");
    codecs[0].pt = PJMEDIA_RTP_PT_NTC;
    codecs[0].type = PJMEDIA_TYPE_AUDIO;
    codecs[0].clock_rate = 16000;
    codecs[0].channel_cnt = 1;

	*count = 1;
	PJ_LOG(5, (THIS_FILE, "ntc_enum_codecs() leaving."));

    return PJ_SUCCESS;
}

static pj_status_t ntc_alloc_codec( pjmedia_codec_factory *factory, 
                                     const pjmedia_codec_info *id,
                                     pjmedia_codec **p_codec)
{
	PJ_LOG(5, (THIS_FILE, "ntc_alloc_codec() entered."));
    pjmedia_codec *codec = NULL;
    pj_status_t status;

	int inst_id = pjmedia_endpt_get_inst_id((pjmedia_endpt *)factory->factory_data);

    PJ_ASSERT_RETURN(factory==&ntc_factory[inst_id].base, PJ_EINVAL);

    /* Lock mutex. */
    pj_mutex_lock(ntc_factory[inst_id].mutex);

    /* Allocate new codec if no more is available */
    if (pj_list_empty(&ntc_factory[inst_id].codec_list)) {
        struct ntc_private *codec_priv;

        codec = PJ_POOL_ALLOC_T(ntc_factory[inst_id].pool, pjmedia_codec);
        codec_priv = PJ_POOL_ZALLOC_T(ntc_factory[inst_id].pool, struct ntc_private);
        if (!codec || !codec_priv) {
			pj_mutex_unlock(ntc_factory[inst_id].mutex);
			PJ_LOG(5, (THIS_FILE, "ntc_alloc_codec() leaving. status=[%d]", PJ_ENOMEM));
            return PJ_ENOMEM;
        }

        /* Set the payload type */
        codec_priv->pt = id->pt;

        /* Create VAD */
        status = pjmedia_silence_det_create(ntc_factory[inst_id].pool,
                                            8000, 80,
                                            &codec_priv->vad);
        if (status != PJ_SUCCESS) {
			pj_mutex_unlock(ntc_factory[inst_id].mutex);
			PJ_LOG(5, (THIS_FILE, "ntc_alloc_codec() leaving. status=[%d]", status));
            return status;
        }

        codec->factory = factory;
        codec->op = &ntc_op;
        codec->codec_data = codec_priv;
    } else {
        codec = ntc_factory[inst_id].codec_list.next;
        pj_list_erase(codec);
    }

    /* Zero the list, for error detection in ntc_dealloc_codec */
    codec->next = codec->prev = NULL;

    *p_codec = codec;

    /* Unlock mutex. */
	pj_mutex_unlock(ntc_factory[inst_id].mutex);
	PJ_LOG(5, (THIS_FILE, "ntc_alloc_codec() leaving. status=[%d]", PJ_SUCCESS));

    return PJ_SUCCESS;
}

static pj_status_t ntc_dealloc_codec(pjmedia_codec_factory *factory, 
                                      pjmedia_codec *codec )
{
	PJ_LOG(5, (THIS_FILE, "ntc_dealloc_codec() entered."));
    struct ntc_private *priv = (struct ntc_private*) codec->codec_data;
	int i = 0;

	int inst_id = pjmedia_endpt_get_inst_id((pjmedia_endpt *)factory->factory_data);

    PJ_ASSERT_RETURN(factory==&ntc_factory[inst_id].base, PJ_EINVAL);

    /* Check that this node has not been deallocated before */
    pj_assert (codec->next==NULL && codec->prev==NULL);
	if (codec->next!=NULL || codec->prev!=NULL) {
		PJ_LOG(5, (THIS_FILE, "ntc_dealloc_codec() leaving. status=[%d]", PJ_EINVALIDOP));
        return PJ_EINVALIDOP;
    }

    PJ_UNUSED_ARG(i);
    PJ_UNUSED_ARG(priv);

    /* Lock mutex. */
    pj_mutex_lock(ntc_factory[inst_id].mutex);

    /* Insert at the back of the list */
    pj_list_insert_before(&ntc_factory[inst_id].codec_list, codec);

    /* Unlock mutex. */
    pj_mutex_unlock(ntc_factory[inst_id].mutex);

	PJ_LOG(5, (THIS_FILE, "ntc_dealloc_codec() leaving. status=[%d]", PJ_SUCCESS));
    return PJ_SUCCESS;
}

static pj_status_t ntc_init( pjmedia_codec *codec, pj_pool_t *pool )
{
	PJ_LOG(5, (THIS_FILE, "ntc_init() entered."));
    /* There's nothing to do here really */
    PJ_UNUSED_ARG(codec);
    PJ_UNUSED_ARG(pool);

	PJ_LOG(5, (THIS_FILE, "ntc_init() leaving. status=[%d]", PJ_SUCCESS));
    return PJ_SUCCESS;
}

static pj_status_t ntc_open(pjmedia_codec *codec, 
                             pjmedia_codec_param *attr )
{
	PJ_LOG(5, (THIS_FILE, "ntc_open() entered."));
    struct ntc_private *priv = (struct ntc_private*) codec->codec_data;
    priv->pt = attr->info.pt;
    priv->vad_enabled = (attr->setting.vad != 0);
	PJ_LOG(5, (THIS_FILE, "ntc_open() leaving."));
    return PJ_SUCCESS;
}

static pj_status_t ntc_close( pjmedia_codec *codec )
{
	PJ_LOG(5, (THIS_FILE, "ntc_close() entered."));
    PJ_UNUSED_ARG(codec);
    /* Nothing to do */
	PJ_LOG(5, (THIS_FILE, "ntc_close() leaving."));
    return PJ_SUCCESS;
}

static pj_status_t  ntc_modify(pjmedia_codec *codec, 
                                const pjmedia_codec_param *attr )
{
	PJ_LOG(5, (THIS_FILE, "ntc_modify() entered."));
    struct ntc_private *priv = (struct ntc_private*) codec->codec_data;

	if (attr->info.pt != priv->pt) {
		PJ_LOG(5, (THIS_FILE, "ntc_modify() leaving. stauts=[%d]", PJMEDIA_EINVALIDPT));
        return PJMEDIA_EINVALIDPT;
	}

    priv->vad_enabled = (attr->setting.vad != 0);

	PJ_LOG(5, (THIS_FILE, "ntc_modify() leaving. stauts=[%d]", PJ_SUCCESS));
    return PJ_SUCCESS;
}

static pj_status_t  ntc_parse( pjmedia_codec *codec,
                                void *pkt,
                                pj_size_t pkt_size,
                                const pj_timestamp *ts,
                                unsigned *frame_cnt,
                                pjmedia_frame frames[])
{
	PJ_LOG(5, (THIS_FILE, "ntc_parse() entered."));
    unsigned count = 0;

    PJ_UNUSED_ARG(codec);

    PJ_ASSERT_RETURN(ts && frame_cnt && frames, PJ_EINVAL);

    while (pkt_size >= FRAME_SIZE && count < *frame_cnt) {
        frames[count].type = PJMEDIA_FRAME_TYPE_AUDIO;
        frames[count].buf = pkt;
        frames[count].size = FRAME_SIZE;
        frames[count].timestamp.u64 = ts->u64 + SAMPLES_PER_FRAME * count;

        pkt = ((char*)pkt) + FRAME_SIZE;
        pkt_size -= FRAME_SIZE;

        ++count;
    }

    *frame_cnt = count;
	PJ_LOG(5, (THIS_FILE, "ntc_parse() leaving."));
    return PJ_SUCCESS;
}

static pj_status_t  ntc_encode(pjmedia_codec *codec, 
                                const struct pjmedia_frame *input,
                                unsigned output_buf_len, 
                                struct pjmedia_frame *output)
{
	PJ_LOG(5, (THIS_FILE, "ntc_encode() entered."));
    pj_int16_t *samples = (pj_int16_t*) input->buf;
    struct ntc_private *priv = (struct ntc_private*) codec->codec_data;

    /* Check output buffer length */
    //if (output_buf_len < (input->size >> 1))
    //    return PJMEDIA_CODEC_EFRMTOOSHORT;

    /* Encode */
	/* we should encrypt the data for security issue */
	pj_memcpy(output->buf, input->buf, input->size);

    output->type = PJMEDIA_FRAME_TYPE_AUDIO;
    output->size = input->size;
    output->timestamp = input->timestamp;

	PJ_LOG(5, (THIS_FILE, "ntc_encode() leaving."));
    return PJ_SUCCESS;
}

static pj_status_t  ntc_decode(pjmedia_codec *codec, 
                                const struct pjmedia_frame *input,
                                unsigned output_buf_len, 
                                struct pjmedia_frame *output)
{
	PJ_LOG(5, (THIS_FILE, "ntc_decode() entered."));
    struct ntc_private *priv = (struct ntc_private*) codec->codec_data;

    /* Check output buffer length */
    //PJ_ASSERT_RETURN(output_buf_len >= (input->size << 1), PJMEDIA_CODEC_EPCMTOOSHORT);

    /* Input buffer MUST have exactly 80 bytes long */
    //PJ_ASSERT_RETURN(input->size == FRAME_SIZE, PJMEDIA_CODEC_EFRMINLEN);

    /* Decode */
	/* we should decrypt the data back for security issue */
	pj_memcpy(output->buf, input->buf, input->size);
	PJ_LOG(5, (THIS_FILE, "ntc_decode() frame=[%s].", (char *)output->buf));

    output->type = PJMEDIA_FRAME_TYPE_AUDIO;
    output->size = input->size;
    output->timestamp = input->timestamp;

	PJ_LOG(5, (THIS_FILE, "ntc_decode() leaving."));
    return PJ_SUCCESS;
}


