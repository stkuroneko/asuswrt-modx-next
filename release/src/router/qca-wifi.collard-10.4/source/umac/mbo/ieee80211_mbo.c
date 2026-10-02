/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

/*
 MBO  module
*/

#include "ieee80211_mbo_priv.h"

#if ATH_SUPPORT_MBO

/**
 * @brief Verify that the mbo handle is valid
 *
 * @param [in] VAP  the handle to the
 *
 * @return true if handle is valid; otherwise false
 */

static INLINE bool ieee80211_mbo_is_valid(const struct ieee80211vap *vap)
{
    return vap && vap->mbo;
}

/**
 * @brief Determine whether the VAP handle is valid,
 *        has a valid mbo handle,
 *        is operating in a mode where MBO is relevant,
 *        and is not in the process of being deleted.
 *
 * @return true if the VAP is valid; otherwise false
 */

bool ieee80211_mbo_is_vap_valid(const struct ieee80211vap *vap)
{
    /* Unfortunately these functions being used do not take a const pointer
       even though they do not modify the VAP. Thus, we have to cast away
       the const-ness in order to call them.*/

    struct ieee80211vap *nonconst_vap = (struct ieee80211vap *) vap;

    return vap && wlan_vap_get_opmode(nonconst_vap) == IEEE80211_M_HOSTAP &&
           !ieee80211_vap_deleted_is_set(nonconst_vap);
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

bool ieee80211_vap_mbo_check(struct ieee80211vap *vap)
{
    if((ieee80211_mbo_is_vap_valid(vap)
        && ieee80211_mbo_is_valid(vap))
        && ieee80211_vap_mbo_is_set(vap))
        return true;
    else
        return false;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */
bool ieee80211_vap_mbo_assoc_status(struct ieee80211vap *vap)
{
    if (vap->mbo->usr_assoc_disallow) 
        return true;
    else 
        return false;
}
void ieee80211_mbo_help(u_int32_t param)
{
    switch(param) {
        case MBO_ATTRIB_CAP_INDICATION:
            {
                printk(" 0th bit- reserved\n");
                printk(" 1st bit- Non-preferred channel report capability\n");
                printk(" 2nd bit- MBO Cellular capabilities\n");
                printk(" 3rd bit- Association disallowed capability\n");
                printk(" 4th bit- Cellular data link request capability\n");
                printk(" 5th-7th bits- reserved\n");
            }
            break;
        case MBO_ATTRIB_ASSOCIATION_DISALLOWED:
            {
                printk(" value 0- reserved\n");
                printk(" value 1- Unspecified reason\n");
                printk(" value 2- Max no. of associated STAs reached\n");
                printk(" value 3- Air interface overloaded\n");
                printk(" value 4- Authentication server overloaded\n");
                printk(" value 5- Insufficient RSSI\n");
                printk(" value 6-255- reserved\n");
            }
            break;
        case MBO_ATTRIB_TRANSITION_REASON:
            {
                printk(" Code 0- unspecified\n");
                printk(" Code 1- Excessive frame loss rate\n");
                printk(" Code 2- Excessive delay for current traffic stream\n");
                printk(" Code 3- Insufficient bandwidth for current traffic stream\n");
                printk(" Code 4- Load balancing\n");
                printk(" Code 5- Low RSSI\n");
                printk(" Code 6- Received excessive number of retransmissions\n");
                printk(" Code 7- High interference\n");
                printk(" Code 8- Gray zone\n");
                printk(" Code 9- Transitioning to premium AP\n");
                printk(" Code 10-255- reserved\n");
            }
            break;
    }
    return;
}
/**
 * set simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : config paramter
 * @param val             : value of the parameter.
 * @return 0  on success and -ve on failure.
 */

int wlan_set_mbo_param(wlan_if_t vap, u_int32_t param, u_int32_t val)
{
    int retv = EOK;
    ieee80211_mbo_t mbo = NULL;

    if(!ieee80211_mbo_is_vap_valid(vap))
        return EINVAL;

    if (!ieee80211_mbo_is_valid(vap))
        return EINVAL;

    mbo = vap->mbo;

    switch(param) {
    case IEEE80211_MBO:
        {
            if(val)
                ieee80211_vap_mbo_set(vap);
            else {
                ieee80211_vap_mbo_clear(vap);
            }
        }
        break;
    case IEEE80211_MBOCAP:
        {
            if (ieee80211_vap_mbo_is_set(vap) ) {
                if(val & MBO_CAP_AP_CELLULAR)
                    mbo->usr_mbocap_cellular_capable =  1;
                else
                    mbo->usr_mbocap_cellular_capable =  0;
            } else {
                printk("Need to enable MBO Before setting capability \n");
                retv = EINVAL;
            }
        }
        break;
    case IEEE80211_MBO_ASSOC_DISALLOW:
        {
#define MBO_MAX_ASSOC_DISALLOW 0x06
            if (!ieee80211_vap_mbo_is_set(vap)) {
                printk("MBO not enabled \n");
                retv = EINVAL;
            } else if (val < MBO_MAX_ASSOC_DISALLOW) {
                mbo->usr_assoc_disallow = (u_int8_t)val;
                vap->iv_flags_ext2 |= IEEE80211_FEXT2_MBO;
            } else {
                printk("__Invalid argument __investigate__ \n");
                ieee80211_mbo_help(MBO_ATTRIB_ASSOCIATION_DISALLOWED);
                retv = EINVAL;
            }
        }
#undef MBO_MAX_ASSOC_DISALLOW
        break;
    case IEEE80211_MBO_CELLULAR_PREFERENCE:
        if ((val <= MBO_CELLULAR_PREFERENCE_NOT_USE) ||
            (val == MBO_CELLULAR_PREFERENCE_USE)) /* as per specification */
            mbo->usr_cell_pref = val;
        else
            retv = EINVAL;
        break;
    case IEEE80211_MBO_TRANSITION_REASON:
        if (val <= MBO_TRANSITION_REASON_PREMIUM_AP ) /* as per specification */
           mbo->usr_trans_reason = val;
        else
            retv = EINVAL;
        break;
    case IEEE80211_MBO_ASSOC_RETRY_DELAY:
        mbo->usr_assoc_retry = val;
        break;
    default:
        printk("Invalid configuration __investigate %s \n",__func__);
        retv = EINVAL;
    }
    return retv;
}


/**
 * get simple configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : paramter.
 * @return value of the parameter.
 */

u_int32_t wlan_get_mbo_param(wlan_if_t vap, u_int32_t param)
{
    u_int32_t retv = 0;
    ieee80211_mbo_t mbo = NULL;

    if(!ieee80211_mbo_is_vap_valid(vap))
        return EINVAL;

    if (!ieee80211_mbo_is_valid(vap))
        return EINVAL;

    mbo = vap->mbo;

    switch(param) {
    case IEEE80211_MBO:
        {
            retv = ieee80211_vap_mbo_is_set(vap);
        }
        break;
    case IEEE80211_MBOCAP:
        {
            if (mbo->usr_mbocap_cellular_capable) {
                retv |= MBO_CAP_AP_CELLULAR;
            }
        }
        break;
    case IEEE80211_MBO_ASSOC_DISALLOW:
        {
            retv = mbo->usr_assoc_disallow;
        }
        break;
    case IEEE80211_MBO_CELLULAR_PREFERENCE:
        return mbo->usr_cell_pref;
    case IEEE80211_MBO_TRANSITION_REASON:
        return mbo->usr_trans_reason;
    case IEEE80211_MBO_ASSOC_RETRY_DELAY:
        return mbo->usr_assoc_retry;
    default:
        printk("Invalid configuration __investigate %s \n",__func__);
        return EINVAL;;
    }
    return retv;
}

/**
 * @brief Initialize the MBO infrastructure.
 *
 * @param [in] vap  to initialize
 *
 * @return EOK on success; EINPROGRESS if band steering is already initialized
 *         or ENOMEM on a memory allocation failure
 */

int ieee80211_mbo_vattach(struct ieee80211vap *vap)
{

    ieee80211_mbo_t mbo = NULL;

    if(!ieee80211_mbo_is_vap_valid(vap))
        return EINVAL;

    printk("%s:MBO Initialized \n",__func__);

    if(vap->mbo)
        return EINPROGRESS;

    mbo = (ieee80211_mbo_t)
        OS_MALLOC(vap->iv_ic->ic_osdev, sizeof(struct ieee80211_mbo), 0);

    if(NULL == mbo) {
        return -ENOMEM;
    }

    OS_MEMZERO(mbo,sizeof(struct ieee80211_mbo));
    mbo->mbo_osdev = vap->iv_ic->ic_osdev;
    mbo->mbo_ic = vap->iv_ic;
    vap->mbo = mbo;

    return EOK;
}

/**
 * @brief deint the MBO infrastructure.
 *
 * @param [in] vap  to deint
 *
 * @return EOK on success;
 */

int ieee80211_mbo_vdetach(struct ieee80211vap *vap)
{
    if (!ieee80211_mbo_is_valid(vap))
        return EINVAL;

    OS_FREE(vap->mbo);
    vap->mbo = NULL;

    printk("%s: MBO terminated\n", __func__);
    return EOK;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

static inline u_int8_t ieee80211_mbo_fill_header(struct ieee80211_mbo_header *header,u_int8_t type,u_int8_t len)
{
    header->ie = type;
    header->len = len;
    return((u_int8_t)sizeof(struct ieee80211_mbo_header));
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_assoc_disallow_ie(struct ieee80211vap *vap,u_int8_t *frm,u_int8_t reason)
{
    struct ieee80211_assoc_disallow *assoc_ie  = (struct ieee80211_assoc_disallow *)frm;
    u_int8_t len = 0;
    len = ieee80211_mbo_fill_header(&(assoc_ie->header),MBO_ATTRIB_ASSOCIATION_DISALLOWED,0);

    assoc_ie->reason_code = reason;
    assoc_ie->header.len = sizeof(struct ieee80211_assoc_disallow) - len;
    frm = (u_int8_t *)(&assoc_ie->opt_ie[0]);
    return (u_int8_t)sizeof(struct ieee80211_assoc_disallow);
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_assoc_retry_del_ie(struct ieee80211vap *vap,u_int8_t *frm,
                                          struct ieee80211_bstm_reqinfo *bstm_reqinfo)
{
    struct ieee80211_assoc_retry_delay *assoc_re_del_ie = (struct ieee80211_assoc_retry_delay *)frm;
    ieee80211_mbo_t mbo = NULL;
    u_int8_t len = 0;
    if ( vap ) {
        mbo = vap->mbo;
    }
    if (mbo == NULL){
        return len;
    }

    len = ieee80211_mbo_fill_header(&(assoc_re_del_ie->header),MBO_ATTRIB_ASSOC_RETRY_DELAY,0);
    assoc_re_del_ie->header.len = (sizeof(struct ieee80211_assoc_retry_delay) - len);
    assoc_re_del_ie->re_auth_delay = cpu_to_le16(mbo->usr_assoc_retry);
    return (u_int8_t)(sizeof(struct ieee80211_assoc_retry_delay));
}


/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_trans_reason_ie(struct ieee80211vap *vap,u_int8_t *frm,struct ieee80211_bstm_reqinfo *bstm_reqinfo)
{
    struct ieee80211_transit_reason_code *trans_reason_code_ie = (struct ieee80211_transit_reason_code *)frm;
    ieee80211_mbo_t mbo = NULL;
    u_int8_t len = 0,len_next_attr = 0;
    if ( vap ) {
        mbo = vap->mbo;
    }
    if (mbo == NULL){
        return len;
    }
    if (mbo->usr_trans_reason <= MBO_TRANSITION_REASON_PREMIUM_AP) {
        len = ieee80211_mbo_fill_header(&(trans_reason_code_ie->header),MBO_ATTRIB_TRANSITION_REASON ,0 );
        trans_reason_code_ie->header.len = (sizeof(struct ieee80211_transit_reason_code) - len);
        trans_reason_code_ie->reason_code = mbo->usr_trans_reason;
        frm = (u_int8_t *)&trans_reason_code_ie->opt_ie[0];
        len = sizeof(struct ieee80211_transit_reason_code);
    }
    if(!bstm_reqinfo->bssterm_inc)
        len_next_attr = ieee80211_setup_assoc_retry_del_ie(vap,frm,bstm_reqinfo);
    return (u_int8_t)(len_next_attr + len);

}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_cell_pref_ie(struct ieee80211vap *vap,u_int8_t *frm,struct ieee80211_bstm_reqinfo *bstm_reqinfo)
{
    struct ieee80211_cell_data_conn_pref *cell_pref_ie = (struct ieee80211_cell_data_conn_pref *)frm;
    ieee80211_mbo_t mbo = NULL;
    u_int8_t len = 0,len_next_attr = 0;
    /*
     * This ie should be sent only when cellular
     * capabilities are supported by the station.
     */

    if ( vap ) {
        mbo = vap->mbo;
    }
    if(mbo == NULL){
        return len;
    }

    len = ieee80211_mbo_fill_header(&(cell_pref_ie->header),MBO_ATTRIB_CELLULAR_PREFERENCE ,0 );
    frm = (u_int8_t *)&cell_pref_ie->opt_ie[0];
    len_next_attr = ieee80211_setup_trans_reason_ie(vap,frm,bstm_reqinfo);
    cell_pref_ie->header.len = (sizeof(struct ieee80211_cell_data_conn_pref)-len);
    cell_pref_ie->cell_pref  = mbo->usr_cell_pref;
    return (u_int8_t)(len_next_attr + sizeof(struct ieee80211_cell_data_conn_pref));

}
/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_mbo_cap_ie(u_int8_t *frm, u_int8_t cellular_aware)
{
    struct ieee80211_mbo_cap *cap = NULL;

    cap = (struct ieee80211_mbo_cap *)frm;
    OS_MEMSET(cap,0,sizeof(struct ieee80211_mbo_cap));
    ieee80211_mbo_fill_header(&(cap->header),
                                    MBO_ATTRIB_CAP_INDICATION,0);

    cap->cap_cellular = cellular_aware; /*Broadcasting this value in frame */
    cap->header.len =  sizeof(struct ieee80211_mbo_cap) -
                       sizeof(struct ieee80211_mbo_header);

    return sizeof(struct ieee80211_mbo_cap);
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t ieee80211_setup_additional_ie(struct ieee80211vap *vap,u_int8_t *frm)
{
    ieee80211_mbo_t mbo = NULL;
    u_int8_t *start = frm;

    /* mbo check already done  in caller */

    mbo = vap->mbo;

	frm += ieee80211_setup_mbo_cap_ie(frm, mbo->usr_mbocap_cellular_capable);
    if(mbo->usr_assoc_disallow) {
        frm += ieee80211_setup_assoc_disallow_ie(vap,frm,
                                                 mbo->usr_assoc_disallow);
    }
    return (frm - start);
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t*
ieee80211_setup_mbo_ie_bstmreq(struct ieee80211vap *vap, u_int8_t *ie,
                               struct ieee80211_bstm_reqinfo *bstm_reqinfo,
                               u_int8_t *macaddr)
{

    u_int8_t len = 0,*frm = NULL;
    struct ieee80211_mbo_ie *mbo_ie = (struct ieee80211_mbo_ie *)ie;
    struct ieee80211_node *ni = NULL;

    if(!mbo_ie)
        return ie;

    ieee80211_mbo_fill_header(&(mbo_ie->header),IEEE80211_ELEMID_VENDOR,0);
    mbo_ie->oui[0] = 0x50;
    mbo_ie->oui[1] = 0x6f;
    mbo_ie->oui[2] = 0x9a;
    mbo_ie->oui_type = MBO_OUI_TYPE;

    frm = (u_int8_t *)&mbo_ie->opt_ie[0];

    /*
     * If cell cap not supported by STA don't send cell_pref_ie
     * To find out if cell cap is supported by this macaddr compare
     * macaddr to macaddr of all STAs connected to vap and when it
     * matches check cell cap description within mbo_attributes structure
     */
     ni = ieee80211_find_node(&vap->iv_ic->ic_sta, macaddr);

     if(!ni)
         return frm;

    if (ni->ni_mbo.cellular_cap == 0x01 )
        len = ieee80211_setup_cell_pref_ie(vap,frm,bstm_reqinfo);
    else
        len = ieee80211_setup_trans_reason_ie ( vap, frm, bstm_reqinfo );
    mbo_ie->header.len = len + (sizeof(struct ieee80211_mbo_ie) - sizeof(struct ieee80211_mbo_header));
    return (frm +len);
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

/*
 * Parse the MBO ie for non-preferred channel report attribute and
 * Cellular capabilities attirbute
 */

int
ieee80211_parse_mboie(u_int8_t *frm, const struct ieee80211_frame *wh,
        struct ieee80211_node *ni)
{
    u_int len = frm[1];
    u_int non_preferred_channel_attribute_len;
    u_int num_chan = 0, non_pref_attribute = 0;
    u_int updated_len = 0;
    u_int slen;
    u_int  attribute_id;
    u_int  attribute_len;
#define MBO_IE_MIN_LEN 4
    if(len < MBO_IE_MIN_LEN){
        IEEE80211_DISCARD_IE(ni->ni_vap,
                IEEE80211_MSG_ELEMID | IEEE80211_MSG_MBO,
                "MBO IE", "too short, len %u", len);
        return -1;
    }

    /* no non-preferred channel report attribute and cellular
       capabilities attribute present*/

    if (len == MBO_IE_MIN_LEN){
        printk(" No attribute id present \n");
        goto end;
    }
    slen = len - 4;
    /*
     * Incrementing frm by 6 so that it will point to the mbo attribute id
     * 1 byte for element id
     * 1 byte for length
     * 3 bytes for MBO OUI
     * 1 byte for MBO OUI type
     */
    frm = frm + 6;

    while(slen > updated_len)
    {
        attribute_id = *frm++;
        switch(attribute_id){
            case MBO_ATTRIB_CELLULAR:
                {
                    attribute_len = *frm++;
                    ni->ni_mbo.cellular_cap = *frm++;
                }
                updated_len += attribute_len + 2;
                break;
            case MBO_ATTRIB_NON_PREFERRED_CHANNEL:
                {
                    non_preferred_channel_attribute_len = *frm++;
                    ni->ni_mbo.num_attr = 0;
                    if (non_preferred_channel_attribute_len == 0){
                        printk("No non preferred channel report \n");
                    }
                    else
                    {
                        if(non_pref_attribute < IEEE80211_MBO_NUM_NONPREF_CHAN_ATTR){
                           OS_MEMSET(ni->ni_mbo.channel[non_pref_attribute].channels,0,
                                     sizeof(ni->ni_mbo.channel[non_pref_attribute].channels));
                            ni->ni_mbo.channel[non_pref_attribute].operating_class = *frm++;
                            ni->ni_mbo.channel[non_pref_attribute].num_channels = non_preferred_channel_attribute_len - 4;
                            for(num_chan = 0; num_chan < ni->ni_mbo.channel[non_pref_attribute].num_channels; num_chan++)
                            {
                                ni->ni_mbo.channel[non_pref_attribute].channels[num_chan] = *frm++;
                            }
                            ni->ni_mbo.channel[non_pref_attribute].channels_preference = *frm++;
                            ni->ni_mbo.channel[non_pref_attribute].reason_preference   = *frm++;
                            ni->ni_mbo.channel[non_pref_attribute].reason_detail  = *frm++;
                            non_pref_attribute++;
                            ni->ni_mbo.num_attr = non_pref_attribute;
                        }
                        else {
                            frm +=len;
                        }
                    }
                }
                updated_len += non_preferred_channel_attribute_len + 2;

                break;
            default:
                break;
        }
    }
end:
#undef MBO_IE_MIN_LEN
    return EOK;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

 /*
  * parse the WNM Notification request frame for mbo ie
  */
int ieee80211_parse_wnm_mbo_subelem(u_int8_t *frm, struct ieee80211_node *ni)
{
    u_int len = frm[1];
    u_int num_chan, non_pref_attribute = 0;
    u_int8_t attribute_id;
    u_int8_t *sfrm;
#define MBO_IE_MIN_LEN 4

    if(len < MBO_IE_MIN_LEN){
        IEEE80211_DISCARD_IE(ni->ni_vap,
                IEEE80211_MSG_ELEMID | IEEE80211_MSG_MBO,
                "MBO IE", "too short, len %u", len);
        return -1;
    }
    /*
     * Incrementing frm by 5 will make it point to the mbo attribute subelement
     * 1 byte for subelement id
     * 1 byte for length
     * 3 bytes for MBO OUI
     */
    sfrm = frm;
    while ((sfrm[0] == IEEE80211_ELEMID_VENDOR) &&
           (sfrm[2] == (MBO_OUI >>  0 & 0xFF)) &&
           (sfrm[3] == (MBO_OUI >>  8 & 0xFF)) &&
           (sfrm[4] == (MBO_OUI >> 16 & 0xFF))) {
        frm = sfrm + 5;
        attribute_id = *frm++;
        if (attribute_id == MBO_ATTRIB_NON_PREFERRED_CHANNEL) {
            // Non preferred channel report sub-element
            len = *(sfrm +1);
            if (len == 4) {
                printk("No non preferred channels list is present \n");
                ni->ni_mbo.num_attr = 0;
            }
            else {
                if(non_pref_attribute < IEEE80211_MBO_NUM_NONPREF_CHAN_ATTR){
                    OS_MEMSET(ni->ni_mbo.channel[non_pref_attribute].channels,0,
                             sizeof(ni->ni_mbo.channel[non_pref_attribute].channels));
                    ni->ni_mbo.channel[non_pref_attribute].operating_class = *frm++;
                    ni->ni_mbo.channel[non_pref_attribute].num_channels = (len == 0) ? 0:len - 8;
                    for(num_chan = 0; num_chan < ni->ni_mbo.channel[non_pref_attribute].num_channels; num_chan++)
                    {
                        ni->ni_mbo.channel[non_pref_attribute].channels[num_chan] = *frm++;
                    }
                    ni->ni_mbo.channel[non_pref_attribute].channels_preference = *frm++;
                    ni->ni_mbo.channel[non_pref_attribute].reason_preference   = *frm++;
                    ni->ni_mbo.channel[non_pref_attribute].reason_detail = *frm;
                    non_pref_attribute++;
                    ni->ni_mbo.num_attr = non_pref_attribute;
                }
            }
            sfrm += len + 2;
        } else if (attribute_id == MBO_ATTRIB_CELLULAR) {             // cellular capabilities sub-element
            len = *(sfrm +1);
            if(len < 5 ){
                printk("No cellular capabilities present \n");
            } else {
                ni->ni_mbo.cellular_cap = *(frm);
            }
            sfrm += len + 2;
        }
    }
#undef MBO_IE_MIN_LEN
    return EOK;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

u_int8_t*
ieee80211_setup_mbo_ie(struct ieee80211vap *vap, u_int8_t *ie)
{
    u_int8_t len = 0,*frm = NULL;
    struct ieee80211_mbo_ie *mbo_ie = (struct ieee80211_mbo_ie *)ie;

    OS_MEMSET(mbo_ie,0x00,sizeof(struct ieee80211_mbo_ie));
    ieee80211_mbo_fill_header(&(mbo_ie->header),IEEE80211_ELEMID_VENDOR,0);
    mbo_ie->oui[0] = 0x50;
    mbo_ie->oui[1] = 0x6f;
    mbo_ie->oui[2] = 0x9a;
    mbo_ie->oui_type = MBO_OUI_TYPE;

    frm = (uint8_t *)&mbo_ie->opt_ie[0];
        //frm += (sizeof(struct ieee80211_mbo_ie)) ;
    len = ieee80211_setup_additional_ie(vap,frm);

    mbo_ie->header.len = len + (sizeof(struct ieee80211_mbo_ie) - sizeof(struct ieee80211_mbo_header));
    return ( frm + len );

}

static void
ieee80211_mbo_operating_class_to_chan(u_int8_t reg_class,
                                      struct ieee80211_node *ni,
                                      u_int16_t countryCode)
{
    /**
     * Country code made available in case it is needed
     */
    switch(reg_class)
    {
        case 1:
        case 115:
            ni->ni_supp_op_cl.channels_supported[36] = true;
            ni->ni_supp_op_cl.channels_supported[40] = true;
            ni->ni_supp_op_cl.channels_supported[44] = true;
            ni->ni_supp_op_cl.channels_supported[48] = true;
            ni->ni_supp_op_cl.num_chan_supported += 4;
            break;
        case 2:
            ni->ni_supp_op_cl.channels_supported[52] = true;
            ni->ni_supp_op_cl.channels_supported[56] = true;
            ni->ni_supp_op_cl.channels_supported[60] = true;
            ni->ni_supp_op_cl.channels_supported[64] = true;
            ni->ni_supp_op_cl.num_chan_supported += 4;
            break;
        case 3:
            ni->ni_supp_op_cl.channels_supported[149] = true;
            ni->ni_supp_op_cl.channels_supported[153] = true;
            ni->ni_supp_op_cl.channels_supported[157] = true;
            ni->ni_supp_op_cl.channels_supported[161] = true;
            ni->ni_supp_op_cl.num_chan_supported += 4;
            break;
        case 4:
            ni->ni_supp_op_cl.channels_supported[100] = true;
            ni->ni_supp_op_cl.channels_supported[104] = true;
            ni->ni_supp_op_cl.channels_supported[108] = true;
            ni->ni_supp_op_cl.channels_supported[112] = true;
            ni->ni_supp_op_cl.channels_supported[116] = true;
            ni->ni_supp_op_cl.channels_supported[120] = true;
            ni->ni_supp_op_cl.channels_supported[124] = true;
            ni->ni_supp_op_cl.channels_supported[128] = true;
            ni->ni_supp_op_cl.channels_supported[132] = true;
            ni->ni_supp_op_cl.channels_supported[136] = true;
            ni->ni_supp_op_cl.channels_supported[140] = true;
            ni->ni_supp_op_cl.num_chan_supported += 11;
            break;
        case 12:
        case 81:
            ni->ni_supp_op_cl.channels_supported[1] = true;
            ni->ni_supp_op_cl.channels_supported[2] = true;
            ni->ni_supp_op_cl.channels_supported[3] = true;
            ni->ni_supp_op_cl.channels_supported[4] = true;
            ni->ni_supp_op_cl.channels_supported[5] = true;
            ni->ni_supp_op_cl.channels_supported[6] = true;
            ni->ni_supp_op_cl.channels_supported[7] = true;
            ni->ni_supp_op_cl.channels_supported[8] = true;
            ni->ni_supp_op_cl.channels_supported[9] = true;
            ni->ni_supp_op_cl.channels_supported[10] = true;
            ni->ni_supp_op_cl.channels_supported[11] = true;
            ni->ni_supp_op_cl.num_chan_supported += 11;
            break;
        default:
            printk("\n missing case for op class %d in %s\n", reg_class, __func__);
            break;
    }
    return;
}

/**
 * @brief
 * @param [in]
 * @param [out]
 */

/**
 * Using info parsed in supported operating classes ie
 * to derive channels that are not supported by STA
 */
int ieee80211_mbo_supp_op_cl_to_non_pref_chan_rpt(struct ieee80211_node *ni, u_int16_t countryCode)
{
    int i;
    ni->ni_supp_op_cl.num_chan_supported = 0;
    /**
     * Initializing array to false. The array index serves
     * as channel number. A false value indicates channel number
     * equal to the value of index of the slot is not supported.
     */
    for (i = 0; i < IEEE80211_CHAN_MAX;i++)
        ni->ni_supp_op_cl.channels_supported[i] = false;
    /**
     * marking true for those channels that are
     * supported by STA
     */
    for (i = 0; i < (ni->ni_supp_op_cl.num_of_supp_class); i++)
    {
        /**
         * Calling function that marks true for
         * those channels that are supported by the STA
         * as obtained from operating class
         */
        ieee80211_mbo_operating_class_to_chan(ni->ni_supp_op_cl.supp_class[i], ni, countryCode);
    }
    return 1;
}

int
ieee80211_parse_op_class_ie(u_int8_t *frm, const struct ieee80211_frame *wh,
                            struct ieee80211_node *ni, u_int16_t countrycode)
{
    int i,opclass_num = 0;

    /**
     * Format of supported operating class IE
     * Elem ID:59( 1 byte )
     * Length: 2-253( 1 byte )
     * Current Operating class( 1 byte )
     * Supported operating classes( Variable )
     */
    opclass_num = ni->ni_supp_op_cl.num_of_supp_class = frm[1];
    ni->ni_supp_op_cl.curr_op_class = frm[2];

    if ( opclass_num ) {
        for (i = 0; i < opclass_num; i++) {
            ni->ni_supp_op_cl.supp_class[i] = frm[i+2];
        }
        ieee80211_mbo_supp_op_cl_to_non_pref_chan_rpt(ni,countrycode);
    }
    return 1;
}

#else
/**
 * set configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : simple config paramaeter.
 * @param val             : value of the parameter.
 * @return 0  on success and -ve on failure.
 */
int wlan_set_mbo_param(wlan_dev_t devhandle, ieee80211_device_param param, u_int32_t val)
{
    return EOK;
}

/**
 * get configuration parameter.
 *
 * @param devhandle       : handle to the vap.
 * @param param           : config paramaeter.
 * @return value of the parameter.
 */
u_int32_t wlan_get_mbo_param(wlan_if_t vap, u_int32_t param)
{
    return EOK;
}

/**
 * @brief Initialize the MBO infrastructure.
 *
 * @param [in] vap  to initialize
 *
 * @return EOK on success; EINPROGRESS if band steering is already initialized
 *         or ENOMEM on a memory allocation failure
 */

int ieee80211_mbo_vattach(struct ieee80211vap *vap)
{
    return EOK;
}

/**
 * @brief deint the MBO infrastructure.
 *
 * @param [in] vap  to deint
 *
 * @return EOK on success;
 */

int ieee80211_mbo_vdetach(struct ieee80211vap *vap)
{

    return EOK;
}

/**
 * @brief setup MBO ie in Beacon infrastructure.
 *
 * @param [in] Vap to intialize beacon.
 *
 * @return frame pointer;
 *
 */

u_int8_t* ieee80211_setup_mbo_ie(struct ieee80211vap *vap, u_int8_t *ie)
{
    return ie;
}


#endif
