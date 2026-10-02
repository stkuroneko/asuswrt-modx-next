/*
** amas-utils.c
**
**
*/
#include <stdio.h>
#include <string.h>
#include "amas-utils-int.h"

/* for onboarding time/timeout */
int reboot_time = 0;
int connection_timeout = 0;
int traffic_timeout = 0;

////////////////////////////////////////////////////////////////////////////////
//
//  Library Initializer & Finalizer
//
////////////////////////////////////////////////////////////////////////////////
void AMAS_API
amas_utils_dll_onload(
    void)
{
    if (pthread_mutex_init(&gLock, NULL) != 0)
    {
        printf("pthread_mutex_init(gLock) failed ...\n");
    }
    return;
}
//---------------------------------------------------------------------------
void AMAS_API
amas_utils_dll_onunload(
    void)
{
    pthread_mutex_destroy(&gLock);
    return;
}
//---------------------------------------------------------------------------
__attribute__((constructor))
static void Initializer(
    int argc,
    char *argv[],
    char **envp)
{
    amas_utils_dll_onload();
    return;
}
//---------------------------------------------------------------------------
__attribute__((destructor))
static void Finalizer(
    void)
{
    amas_utils_dll_onunload();
    return;
}
//---------------------------------------------------------------------------
AMAS_FUNC char*
AMAS_API amas_utils_version_text(
    void)
{
    static char libVersionText[MAX_VERSION_TEXT_LENGTH+4];
    char ssl_version[32];

    memset(ssl_version, 0, sizeof(ssl_version));
    memset(libVersionText, 0, sizeof(libVersionText));
    snprintf(libVersionText, sizeof(libVersionText)-4, "%s/%d.%d.%d.%d %s/%s %s",
        SZ_LIBRARY_NAME,
        AMASUTILS_MAJOR_NUMBER,
        AMASUTILS_MINOR_NUMBER,
        AMASUTILS_RESVISION_NUMBER,
        AMASUTILS_BUILD_NUMBER,
        "json-c",
        json_c_version(),
        ssl_version_text(ssl_version));
    return (char*)libVersionText;
}
//---------------------------------------------------------------------------
AMAS_FUNC char*
AMAS_API amas_utils_str_error(
    AMAS_RESULT code)
{
    char *str = NULL;
    FIND_ERRCODE_BY_CONTEXT(code, str);
    return str;
}

//---------------------------------------------------------------------------
AMAS_FUNC void
AMAS_API amas_utils_set_debug(
    unsigned int enable)
{
    AdvDBG_Enable(ADVDBG_DEBUG,ADVDBG_LOG_TITLE|ADVDBG_LOG_PID);
    Write_ShowDebug(enable);
    return;
}
//---------------------------------------------------------------------------
#if defined(USE_GET_TLV_SUPPORT_MAC)
AMAS_FUNC AMAS_RESULT
AMAS_API amas_get_cost(
    char *ifname,
    int bandindex,
    int capability5g,
    char *ifmac,
    int *cost)
#else   // USE_GET_TLV_SUPPORT_MAC
AMAS_FUNC AMAS_RESULT
AMAS_API amas_get_cost(
    char *ifname,
    int bandindex,
    int capability5g,
    int *cost)
#endif  // USE_GET_TLV_SUPPORT_MAC
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;

#if !defined(USE_GET_TLV_SUPPORT_MAC)
    if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_cost_Fail;
    }
#endif  // !USE_GET_TLV_SUPPORT_MAC

    if (IsNULL_PTR(cost))
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_cost_Fail;
    }

#if defined(USE_LLDP_CTRL)
    v = lldp_get_cost(ifname, ifmac, &res);
#else
#if defined(USE_GET_TLV_SUPPORT_MAC)
    v = LLDP_NBR_TLV_GET_INT_MIN(ifname, bandindex, capability5g, ifmac, AMAS_SUBTYPE_COST, &res);
#else   // USE_GET_TLV_SUPPORT_MAC
    v = LLDP_NBR_TLV_GET_INT_MIN(ifname, bandindex, capability5g, AMAS_SUBTYPE_COST, &res);
#endif  // USE_GET_TLV_SUPPORT_MAC
#endif	/* USE_LLDP_CTRL */
    if (res != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_get_cost_Fail;
    }
    if (!IsNULL_PTR(cost)) *(cost) = v;
    RETURN_AMAS_RESULT_SUCCESS;

amas_get_cost_Fail:
    if (!IsNULL_PTR(cost)) *(cost) = -1;
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_cost(
    int cost)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    char *vsie_id = NULL;
    size_t vsie_id_size = 0;
    int ts = time((time_t *)NULL);

    vsie_id = gen_vsie_id(ts, &vsie_id_size);
    if (IsNULL_PTR(vsie_id))
    {
        SET_ERROR_CODE(AMAS_RESULT_GEN_VSIEID_FAILED);
        goto amas_set_cost_Fail;
    }

    if (vsie_id_size != (MAX_VSIEID_LENGTH*2))
    {
        SET_ERROR_CODE(AMAS_RESULT_GEN_VSIEID_FAILED);
        goto amas_set_cost_Fail;
    }

#if defined(USE_LLDP_CTRL)
    if ((res = lldp_set_cost(vsie_id, vsie_id_size, cost)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_cost_Fail;
    }
#else
    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_ID, vsie_id, vsie_id_size)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_cost_Fail;
    }

    if ((res = LLDP_NBR_TLV_SET_INT(AMAS_SUBTYPE_COST, cost)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_cost_Fail;
    }
#endif	/* USE_LLDP_CTRL */

    MFREE(vsie_id);
    RETURN_AMAS_RESULT_SUCCESS;

amas_set_cost_Fail:
    if (!IsNULL_PTR(vsie_id)) MFREE(vsie_id);
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
int get_entry_count()
{

    FILE *file = NULL;

    json_object *NeighborListObj = NULL;
    json_object *InterfaceData = NULL;
    json_object *ArrayData1 = NULL;
    int ArrayData1Len = 0;

    remove(SZ_LLDP_SHOW_OBD_OUTFNAME);
    doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_OBD_OUTFNAME);

    printf("%s:%d Output neighbor to %s\n", __FUNCTION__, __LINE__, SZ_LLDP_SHOW_OBD_OUTFNAME);
    if (NeighborListObj)
    {

        json_object_object_get_ex(NeighborListObj, "lldp", &InterfaceData);
        if (InterfaceData)
        {
            json_object_object_get_ex(InterfaceData, "interface", &ArrayData1);
            if (ArrayData1)
            {
                ArrayData1Len = json_object_array_length(ArrayData1);
                return ArrayData1Len;
            }
        }
    }
    return 0;
}
//---------------------------------------------------------------------------

int  remove_unnecessary_data(ob_status *P_obstatus, ob_status *P_obsata, int nItem)
{

    unsigned i = 0, last_pos=0;
    int j =0;
    int skip = 0;

    if(P_obstatus==NULL)
        return 0U;

    for(i=0; i<nItem; i++)
    {
        if(isNull(P_obstatus[i].neighmac, sizeof(P_obstatus[i].neighmac)) ||  P_obstatus[i].obstatus == 0){
            continue;
        }

        if (i == 0) {
            memcpy(P_obsata[i].neighmac, P_obstatus[i].neighmac, sizeof(P_obsata[i].neighmac));
            memcpy(P_obsata[i].modelname, P_obstatus[i].modelname, sizeof(P_obsata[i].modelname));
            memcpy(P_obsata[i].tcode, P_obstatus[i].tcode, sizeof(P_obsata[i].tcode));
            memcpy(P_obsata[i].miscinfo, P_obstatus[i].miscinfo, sizeof(P_obsata[i].miscinfo));
            P_obsata[i].obstatus = P_obstatus[i].obstatus;
            P_obsata[i].timestamp = P_obstatus[i].timestamp;
            P_obsata[i].reboottime = P_obstatus[i].reboottime;
            P_obsata[i].conntimeout = P_obstatus[i].conntimeout;
            P_obsata[i].traffictimeout = P_obstatus[i].traffictimeout;
            P_obsata[i].type = P_obstatus[i].type;

            last_pos++;

        }
        else {
            for(j=0; j < nItem; j++)
            {
                 skip = 0;
                 if(!memcmp(P_obstatus[i].neighmac, P_obsata[j].neighmac, sizeof(P_obstatus[i].neighmac)))
                {

                    if (P_obstatus[i].obstatus != P_obsata[j].obstatus) {
                        //DBG_INFO("P_obstatus[%d].obstatus(%d) is different with P_obsata[%d].obstatus(%d).\n", i, P_obstatus[i].obstatus, j, P_obsata[j].obstatus);
                        skip = 0;
                    }
                    else {
                       //DBG_INFO("P_obstatus[%d].neighmac(%02X) at P_obsata[%d]\n",i, P_obsata[j].neighmac[0], j);
                       skip = 1;
                    }
                    break;
                }

            }

            if (skip == 0) {
                memcpy(P_obsata[last_pos].neighmac, P_obstatus[i].neighmac, sizeof(P_obsata[last_pos].neighmac));
                memcpy(P_obsata[last_pos].modelname, P_obstatus[i].modelname, sizeof(P_obsata[last_pos].modelname));
                memcpy(P_obsata[last_pos].tcode, P_obstatus[i].tcode, sizeof(P_obsata[last_pos].tcode));
                memcpy(P_obsata[last_pos].miscinfo, P_obstatus[i].miscinfo, sizeof(P_obsata[last_pos].miscinfo));
                P_obsata[last_pos].obstatus = P_obstatus[i].obstatus;
                P_obsata[last_pos].timestamp = P_obstatus[i].timestamp;
                P_obsata[last_pos].reboottime = P_obstatus[i].reboottime;
                P_obsata[last_pos].conntimeout = P_obstatus[i].conntimeout;
                P_obsata[last_pos].traffictimeout = P_obstatus[i].traffictimeout;
                P_obsata[last_pos].type = P_obstatus[i].type;

                //DBG_INFO("Add new entry P_obstatus[%d].neighmac(%02X) is add to P_obsata[%d].neighbmac = %02X\n", i, P_obstatus[i].neighmac[0], last_pos, P_obsata[last_pos].neighmac[0]);
                last_pos++;

            }


        }

    }
    return last_pos;

}

AMAS_FUNC AMAS_RESULT
AMAS_API  amas_get_obstatus(ob_status **P_obstatus, int *len)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;
    FILE *file = NULL;

    json_object *NeighborListObj = NULL;
    json_object *InterfaceData = NULL;
    json_object *ArrayData1 = NULL;
    json_object *ArrayKeyData = NULL;
    json_object *TLVsData = NULL;
    json_object *TLVData = NULL;
    json_object *subtype = NULL;
    json_object *subtypeVal = NULL;
    json_object *TLVSentry = NULL;
    json_object *TLVentry = NULL;
    json_object *ValueLen = NULL;
    json_object *Port = NULL, *Descr = NULL;

    ob_status *Pobstatus = NULL;

    ob_status *Pobdata = NULL;

    int ArrayData1Len = 0;
    int TLVDataLen = 0;
    int k = 0, j = 0, q = 0;
    int cnt = 0;
    int type = ETH_TYPE_NONE;

    //unsigned char *OriValue = NULL;
    unsigned char OriValue[MAX_VERSION_TEXT_LENGTH + 1] = {0};
    int OriValueLen = 0;

    remove(SZ_LLDP_SHOW_OBD_OUTFNAME);
    doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_OBD_OUTFNAME);

    NeighborListObj = json_object_from_file(SZ_LLDP_SHOW_OBD_OUTFNAME);

    DBG_INFO("%s:%d Output neighbor to %s", __FUNCTION__, __LINE__, SZ_LLDP_SHOW_OBD_OUTFNAME);
    if (NeighborListObj)
    {
        json_object_object_get_ex(NeighborListObj, "lldp", &InterfaceData);
        if (InterfaceData)
        {
            json_object_object_get_ex(InterfaceData, "interface", &ArrayData1);

            if (ArrayData1)
            {
                if (json_object_get_type(ArrayData1) == json_type_array)
                {
                    ArrayData1Len = json_object_array_length(ArrayData1);

                    Pobstatus = (struct _ob_status *) malloc(ArrayData1Len *sizeof(struct _ob_status));

                    memset(Pobstatus, 0x00, ArrayData1Len *sizeof(struct _ob_status));

                    DBG_INFO("%s:%d ArrayData1Len = %d", __FUNCTION__, __LINE__, ArrayData1Len);

                    for (k = 0; k < ArrayData1Len; k++)
                    {
                        TLVSentry = json_object_array_get_idx(ArrayData1, k);

                        json_object_object_foreach(TLVSentry, key, ArrayKeyData)
                        {
                            DBG_INFO("%s:%d interface = %s", __FUNCTION__, __LINE__, key);

                            /* get type by ifname */
                            type = get_type_by_ifname(key);

                            if(ArrayKeyData)
                            {
                                json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                                if (TLVsData)
                                {
                                    json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                    if (json_object_get_type(TLVData) != json_type_array)
                                        goto amas_get_obstatus_Fail;

                                    TLVDataLen = json_object_array_length(TLVData);

                                    for (j = 0; j < TLVDataLen; j++)
                                    {
                                        TLVentry = json_object_array_get_idx(TLVData, j);
                                        json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                        json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                        if (ValueLen) {
                                            OriValueLen = json_object_get_int(ValueLen);
                                            //OriValue = malloc(OriValueLen * sizeof(unsigned char));
                                            memset(OriValue, 0x00, sizeof(OriValue));
                                        }
                                        if (subtype) {
                                            DBG_INFO("%s:%d subtype = %d", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_OBSTATUS) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {

                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     HEXVAL(OriValue,  Pobstatus[k].obstatus, OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Pobstatus[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_MODELNAME) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     ASCII2STR(OriValue,  Pobstatus[k].modelname, OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_TCODE) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     ASCII2STR(OriValue,  Pobstatus[k].tcode, OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_MISC_INFO) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Pobstatus[k].miscinfo, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_TIMESTAMP) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     HEXVAL(OriValue,  Pobstatus[k].timestamp, OriValueLen);

                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_REBOOT_TIME) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     HEXVAL(OriValue,  Pobstatus[k].reboottime, OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_CONN_TIMEOUT) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     HEXVAL(OriValue,  Pobstatus[k].conntimeout, OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_TRAFFIC_TIMEOUT) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     HEXVAL(OriValue,  Pobstatus[k].traffictimeout, OriValueLen);
                                                }
                                            }

                                            Pobstatus[k].type = type;

                                        DBG_INFO("############################################################");
                                        DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X",__FUNCTION__,__LINE__, k, Pobstatus[k].neighmac[0], Pobstatus[k].neighmac[1], Pobstatus[k].neighmac[2], Pobstatus[k].neighmac[3], Pobstatus[k].neighmac[4], Pobstatus[k].neighmac[5]);
                                        DBG_INFO("%s:%d  Entry[%d] ob status = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].obstatus);
                                        DBG_INFO("%s:%d  Entry[%d] ob status Timestamp = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].timestamp);
                                        DBG_INFO("%s:%d  Entry[%d] ob status Model Name = %s", __FUNCTION__, __LINE__,k, Pobstatus[k].modelname);
                                        DBG_INFO("%s:%d  Entry[%d] ob status Tcode = %s", __FUNCTION__, __LINE__,k, Pobstatus[k].tcode);
                                        DBG_INFO("%s:%d  Entry[%d] ob status Reboot Time = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].reboottime);
                                        DBG_INFO("%s:%d  Entry[%d] ob status Connection Timeout = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].conntimeout);
                                        DBG_INFO("%s:%d  Entry[%d] ob status Traffic Timeout = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].traffictimeout);
                                        DBG_INFO("%s:%d  Entry[%d] ob status Type = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].type);
                                        DBG_INFO("%s:%d  Entry[%d] ob status Misc Info =", __FUNCTION__,__LINE__, k);
                                        for(q = 0; q < sizeof(Pobstatus[k].miscinfo); q++) {
                                            if (Pobstatus[k].miscinfo[q] == '\0') break;
                                            DBG_INFO("%02X ", Pobstatus[k].miscinfo[q]);
                                        }
                                        DBG_INFO("############################################################");

                                        }
                                        else
                                            goto amas_get_obstatus_Fail;

                                    }

                                }
                            }
                        }

                    }
                }
                else {
                    ArrayData1Len = 1;
                    Pobstatus = (struct _ob_status *) malloc(ArrayData1Len *sizeof(struct _ob_status));
                    memset(Pobstatus, 0x00, ArrayData1Len *sizeof(struct _ob_status));
                    DBG_INFO("%s:%d ArrayData1Len = %d", __FUNCTION__, __LINE__, ArrayData1Len);

                    json_object_object_foreach(ArrayData1, key, ArrayKeyData)
                    {
                        DBG_INFO("%s:%d interface = %s", __FUNCTION__, __LINE__, key);

                        /* get type by ifname */
                        type = get_type_by_ifname(key);

                        if(ArrayKeyData)
                        {
                            json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                            if (TLVsData)
                            {
                                json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                if (json_object_get_type(TLVData) != json_type_array)
                                    goto amas_get_obstatus_Fail;

                                TLVDataLen = json_object_array_length(TLVData);

                                for (j = 0; j < TLVDataLen; j++)
                                {

                                    TLVentry = json_object_array_get_idx(TLVData, j);

                                    json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                    json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                    if (ValueLen) {
                                        OriValueLen = json_object_get_int(ValueLen);
                                        //OriValue = malloc(OriValueLen * sizeof(char));
                                        memset(OriValue, 0x00, sizeof(OriValue));
                                    }
                                    if (subtype) {
                                        DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_OBSTATUS) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d  json_object_get_string(subtypeVal) = %s", __FUNCTION__, __LINE__,  json_object_get_string(subtypeVal));
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 HEXVAL(OriValue,  Pobstatus[k].obstatus, OriValueLen);
                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d  json_object_get_string(subtypeVal) = %s", __FUNCTION__, __LINE__,  json_object_get_string(subtypeVal));
                                                 STR2HEX(Pobstatus[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_MODELNAME) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d  json_object_get_string(subtypeVal) = %s", __FUNCTION__, __LINE__,  json_object_get_string(subtypeVal));
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 ASCII2STR(OriValue,  Pobstatus[k].modelname, OriValueLen);
                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_TCODE) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d  json_object_get_string(subtypeVal) = %s", __FUNCTION__, __LINE__,  json_object_get_string(subtypeVal));
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 ASCII2STR(OriValue,  Pobstatus[k].tcode, OriValueLen);
                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_MISC_INFO) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d  json_object_get_string(subtypeVal) = %s", __FUNCTION__, __LINE__,  json_object_get_string(subtypeVal));
                                                 STR2HEX(Pobstatus[k].miscinfo, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_TIMESTAMP) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d  json_object_get_string(subtypeVal) = %s", __FUNCTION__, __LINE__,  json_object_get_string(subtypeVal));
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 HEXVAL(OriValue,  Pobstatus[k].timestamp, OriValueLen);

                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_REBOOT_TIME) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d  json_object_get_string(subtypeVal) = %s", __FUNCTION__, __LINE__,  json_object_get_string(subtypeVal));
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 HEXVAL(OriValue,  Pobstatus[k].reboottime, OriValueLen);

                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_CONN_TIMEOUT) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d  json_object_get_string(subtypeVal) = %s", __FUNCTION__, __LINE__,  json_object_get_string(subtypeVal));
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 HEXVAL(OriValue,  Pobstatus[k].conntimeout, OriValueLen);

                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_TRAFFIC_TIMEOUT) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d  json_object_get_string(subtypeVal) = %s", __FUNCTION__, __LINE__,  json_object_get_string(subtypeVal));
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 HEXVAL(OriValue,  Pobstatus[k].traffictimeout, OriValueLen);

                                            }
                                        }

                                        Pobstatus[k].type = type;
                                    }
                                    else
                                        goto amas_get_obstatus_Fail;

                                }
                                    DBG_INFO("############################################################");
                                    DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X",__FUNCTION__,__LINE__, k, Pobstatus[k].neighmac[0], Pobstatus[k].neighmac[1], Pobstatus[k].neighmac[2], Pobstatus[k].neighmac[3], Pobstatus[k].neighmac[4], Pobstatus[k].neighmac[5]);
                                    DBG_INFO("%s:%d  Entry[%d] ob status = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].obstatus);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Timestamp = %X", __FUNCTION__, __LINE__,k, Pobstatus[k].timestamp);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Model Name = %s", __FUNCTION__, __LINE__,k, Pobstatus[k].modelname);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Tcode = %s", __FUNCTION__, __LINE__,k, Pobstatus[k].tcode);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Reboot Time = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].reboottime);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Connection Timeout = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].conntimeout);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Traffic Timeout = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].traffictimeout);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Type = %d", __FUNCTION__, __LINE__,k, Pobstatus[k].type);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Misc Info =", __FUNCTION__,__LINE__, k);
                                    for(q = 0; q < sizeof(Pobstatus[k].miscinfo); q++) {
                                        if (Pobstatus[k].miscinfo[q] == '\0') break;
                                        DBG_INFO("%02X ", Pobstatus[k].miscinfo[q]);
                                    }
                                    DBG_INFO("############################################################");
                            }
                        }
                    }
                }
            }
        }

    }
    if (ArrayData1Len > 0) {
        Pobdata = (struct _ob_status *) malloc(ArrayData1Len *sizeof(struct _ob_status));
        memset(Pobdata, 0x00, ArrayData1Len *sizeof(struct _ob_status));
        cnt = remove_unnecessary_data(Pobstatus, Pobdata, ArrayData1Len);

        DBG_INFO("Entry count = %u", cnt);

        for(k=0; k<cnt; k++) {
            DBG_INFO("Entry(%d) %02X:%02X:%02X:%02X:%02X:%02X %s %s %d %d %d %d %d %d", k, Pobdata[k].neighmac[0],Pobdata[k].neighmac[1],Pobdata[k].neighmac[2],Pobdata[k].neighmac[3],Pobdata[k].neighmac[4],Pobdata[k].neighmac[5],
             Pobdata[k].modelname, Pobdata[k].tcode, Pobdata[k].obstatus, Pobdata[k].timestamp,
             Pobdata[k].reboottime, Pobdata[k].conntimeout, Pobdata[k].traffictimeout, Pobdata[k].type);
        }

        if(cnt > 0) {
            *P_obstatus = (struct _ob_status *) Pobdata;
        }

        else if (cnt == 0) {
            free(Pobdata);
        }

    }


    if (!IsNULL_PTR(len)) *(len) = cnt;

    if (NeighborListObj)
        json_object_put(NeighborListObj);


    if (Pobstatus)
        free(Pobstatus);

    RETURN_AMAS_RESULT_SUCCESS;

amas_get_obstatus_Fail:
    if (NeighborListObj)
        json_object_put(NeighborListObj);

    if (Pobstatus)
        free(Pobstatus);


        RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_obstatus(
    int status)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    char DevMac[18] = {0};
    unsigned char MACaddr[7] = {0};
    int ts = time((time_t *)NULL);

    char ModelName[64]={0}, TCode[16]={0};
    unsigned char *ASCIIModelName = NULL, *ASCIITCode = NULL;
    unsigned char MiscInfo[128], *ASCIIMiscInfo = NULL;;
    int MiscInfoLen = 0;

    if (status == 0) {
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_DEVMAC);
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_TIMESTAMP);
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_MODELNAME);
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_TCODE);
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_OBSTATUS);
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_REBOOT_TIME);
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_CONN_TIMEOUT);
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_TRAFFIC_TIMEOUT);
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_MISC_INFO);
        RETURN_AMAS_RESULT_SUCCESS;
    }

#if defined(RTCONFIG_AMAS_UNIQUE_MAC)
    memcpy(DevMac,  get_label_mac(), sizeof(DevMac));
#else
    memcpy(DevMac,  get_lan_hwaddr(), sizeof(DevMac));
#endif
    STR2HEX(MACaddr , DevMac, 6);
    memset(DevMac, 0x00, sizeof(DevMac));
    sprintf(DevMac, "%02X%02X%02X%02X%02X%02X", MACaddr[0], MACaddr[1], MACaddr[2], MACaddr[3], MACaddr[4], MACaddr[5]);

    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_DEVMAC, DevMac, strlen(DevMac))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_obstatus_Fail;
    }

    if ((res = LLDP_NBR_TLV_SET_INT(AMAS_SUBTYPE_TIMESTAMP, ts)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_obstatus_Fail;
    }

    memcpy(ModelName, get_productid(), sizeof(ModelName));
    memcpy(TCode, nvram_safe_get("territory_code"), sizeof(TCode));

    ASCIIModelName = malloc(strlen(ModelName)* 3 * sizeof(char));
    memset(ASCIIModelName, 0x00, sizeof(ASCIIModelName));

    Hex2String(ASCIIModelName, ModelName, strlen(ModelName));

    if (strlen(TCode)) {
        ASCIITCode = malloc(strlen(TCode)* 3 * sizeof(char));
        if (ASCIITCode) {
            memset(ASCIITCode, 0x00, sizeof(ASCIITCode));
            Hex2String(ASCIITCode, TCode, strlen(TCode));
        }
    }

    amas_get_misc_info((unsigned char *)&MiscInfo, &MiscInfoLen);
    if (MiscInfoLen > 0) {
        ASCIIMiscInfo = malloc(MiscInfoLen* 3 * sizeof(char));
        if (ASCIIMiscInfo) {
            memset(ASCIIMiscInfo, 0x00, sizeof(ASCIIMiscInfo));
            Hex2String(ASCIIMiscInfo, MiscInfo, MiscInfoLen);
        }
    }

    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_MODELNAME, ASCIIModelName, strlen(ASCIIModelName))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_obstatus_Fail;
    }

    if (ASCIITCode && (res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_TCODE, ASCIITCode, strlen(ASCIITCode))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_obstatus_Fail;
    }

    if (ASCIIMiscInfo && (res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_MISC_INFO, ASCIIMiscInfo, strlen(ASCIIMiscInfo))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_obstatus_Fail;
    }

    if ((res = LLDP_NBR_TLV_SET_INT(AMAS_SUBTYPE_OBSTATUS, status)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_obstatus_Fail;
    }

    if (status == 3)
    {
        if ((res = LLDP_NBR_TLV_SET_INT(AMAS_SUBTYPE_REBOOT_TIME, reboot_time)) != AMAS_RESULT_SUCCESS)
        {
            SET_ERROR_CODE(res);
            goto amas_set_obstatus_Fail;
        }

        if ((res = LLDP_NBR_TLV_SET_INT(AMAS_SUBTYPE_CONN_TIMEOUT, connection_timeout)) != AMAS_RESULT_SUCCESS)
        {
            SET_ERROR_CODE(res);
            goto amas_set_obstatus_Fail;
        }

        if ((res = LLDP_NBR_TLV_SET_INT(AMAS_SUBTYPE_TRAFFIC_TIMEOUT, traffic_timeout)) != AMAS_RESULT_SUCCESS)
        {
            SET_ERROR_CODE(res);
            goto amas_set_obstatus_Fail;
        }
    }

    if(ASCIIModelName != NULL)
        free(ASCIIModelName);

    if(ASCIITCode != NULL)
        free(ASCIITCode);

    if(ASCIIMiscInfo != NULL)
        free(ASCIIMiscInfo);

    RETURN_AMAS_RESULT_SUCCESS;

amas_set_obstatus_Fail:

    if(ASCIIModelName != NULL)
        free(ASCIIModelName);

    if(ASCIITCode != NULL)
        free(ASCIITCode);

    if(ASCIIMiscInfo != NULL)
        free(ASCIIMiscInfo);

    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API  amas_get_peermac(unsigned char *macaddr)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;
    FILE *file = NULL;

    json_object *NeighborListObj = NULL;
    json_object *InterfaceData = NULL;
    json_object *ArrayData1 = NULL;
    json_object *ArrayKeyData = NULL;
    json_object *TLVsData = NULL;
    json_object *TLVData = NULL;
    json_object *subtype = NULL;
    json_object *subtypeVal = NULL;
    json_object *TLVSentry = NULL;
    json_object *TLVentry = NULL;
    json_object *ValueLen = NULL;

    int ArrayData1Len = 0;
    int TLVDataLen = 0;
    int k = 0, j = 0;

    unsigned char temp[7]={0};

    //unsigned char *OriValue = NULL;
    int OriValueLen = 0;
    remove(SZ_LLDP_SHOW_OBD_OUTFNAME);
    doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_OBD_OUTFNAME);

    NeighborListObj = json_object_from_file(SZ_LLDP_SHOW_OBD_OUTFNAME);

    DBG_INFO("%s:%d Output neighbor to %s\n", __FUNCTION__, __LINE__, SZ_LLDP_SHOW_OBD_OUTFNAME);
    if (NeighborListObj)
    {
        json_object_object_get_ex(NeighborListObj, "lldp", &InterfaceData);
        if (InterfaceData)
        {
            json_object_object_get_ex(InterfaceData, "interface", &ArrayData1);
            if (ArrayData1)
            {

                if (json_object_get_type(ArrayData1) == json_type_array)
                {
                    ArrayData1Len = json_object_array_length(ArrayData1);

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    for (k = 0; k < ArrayData1Len; k++)
                    {
                        TLVSentry = json_object_array_get_idx(ArrayData1, k);

                        json_object_object_foreach(TLVSentry, key, ArrayKeyData)
                        {
                            DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                            if(ArrayKeyData)
                            {
                                json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                                if (TLVsData)
                                {
                                    json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                    if (json_object_get_type(TLVData) != json_type_array)
                                        goto amas_get_peermac_Fail;

                                    TLVDataLen = json_object_array_length(TLVData);

                                    for (j = 0; j < TLVDataLen; j++)
                                    {
                                        TLVentry = json_object_array_get_idx(TLVData, j);
                                        json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                        json_object_object_get_ex(TLVentry, "len", &ValueLen);

                                        if (ValueLen) {
                                            OriValueLen = json_object_get_int(ValueLen);
                                        }

                                        if (subtype) {
                                            DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));


                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(macaddr, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }

                                        DBG_INFO("############################################################\n");
                                        DBG_INFO("%s:%d Peer's MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
                                        DBG_INFO("############################################################\n");

                                        }
                                        else
                                            goto amas_get_peermac_Fail;
                                    }

                                }
                            }
                        }

                    }
                }
                else
                {
                    ArrayData1Len = 1;
                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);
                    json_object_object_foreach(ArrayData1, key, ArrayKeyData)
                    {
                        DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                        if(ArrayKeyData)
                        {
                            json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                            if (TLVsData)
                            {
                                json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                if (json_object_get_type(TLVData) != json_type_array)
                                    goto amas_get_peermac_Fail;

                                TLVDataLen = json_object_array_length(TLVData);
                                DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);

                                for (j = 0; j < TLVDataLen; j++)
                                {
                                    TLVentry = json_object_array_get_idx(TLVData, j);
                                    json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                    json_object_object_get_ex(TLVentry, "len", &ValueLen);

                                    if (ValueLen) {
                                        OriValueLen = json_object_get_int(ValueLen);
                                        DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);

                                    }

                                    if (subtype) {
                                        DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));


                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d macaddr = (%s) OriValueLen = (%d)\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal), OriValueLen);
                                                 STR2HEX(macaddr, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }


                                    DBG_INFO("############################################################\n");
                                    DBG_INFO("%s:%d Peer's MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
                                    DBG_INFO("############################################################\n");
                                    }
                                    else
                                        goto amas_get_peermac_Fail;
                                }

                            }
                        }
                    }

                }
            }
        }

    }

    if (NeighborListObj)
        json_object_put(NeighborListObj);


    RETURN_AMAS_RESULT_SUCCESS;

amas_get_peermac_Fail:
    if (NeighborListObj)
        json_object_put(NeighborListObj);

        RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_peermac(
    unsigned char *macaddr)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    char DevMac[18] = {0};
    unsigned char MACaddr[7] = {0};

    if(!memcmp(macaddr, "none", 4) || !memcmp(macaddr, "NONE", 4)) {
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_PEERMAC);
        RETURN_AMAS_RESULT_SUCCESS;
    }

    memcpy(DevMac,  macaddr, sizeof(DevMac));
    STR2HEX(MACaddr , DevMac, 6);
    memset(DevMac, 0x00, sizeof(DevMac));
    sprintf(DevMac, "%02X%02X%02X%02X%02X%02X", MACaddr[0], MACaddr[1], MACaddr[2], MACaddr[3], MACaddr[4], MACaddr[5]);

    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_PEERMAC, DevMac, strlen(DevMac))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_peermac_Fail;
    }


    RETURN_AMAS_RESULT_SUCCESS;

amas_set_peermac_Fail:

    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
int  remove_unnecessary_security_status_data(sec_status *P_secstatus, sec_status *P_secsata, int nItem)
{

    unsigned i = 0, last_pos=0;
    int j =0;
    int skip = 0;

    if(P_secstatus==NULL)
        return 0U;

    for(i=0; i<nItem; i++)
    {

        if(isNull(P_secstatus[i].neighmac, sizeof(P_secstatus[i].neighmac)) ||  P_secstatus[i].secstatus == 0)
            continue;


        if (i == 0) {
            memcpy(P_secsata[i].neighmac, P_secstatus[i].neighmac, sizeof(P_secsata[i].neighmac));
            P_secsata[i].secstatus = P_secstatus[i].secstatus;
            memcpy(P_secsata[i].peermac, P_secstatus[i].peermac, sizeof(P_secsata[i].peermac));
            last_pos++;
        }
        else {
            for(j=0; j < nItem; j++)
            {
                 skip = 0;
                 if(!memcmp(P_secstatus[i].neighmac, P_secsata[j].neighmac, sizeof(P_secstatus[i].neighmac)))
                {

                    if (P_secstatus[i].secstatus != P_secsata[j].secstatus) {
                        DBG_INFO("P_secstatus[%d].secstatus(%d) is different with P_secsata[%d].secstatus(%d).\n", i, P_secstatus[i].secstatus, j, P_secsata[j].secstatus);
                        skip = 0;
                    }
                    else {
                       DBG_INFO("P_secstatus[%d].neighmac(%02X) at P_secsata[%d]\n",i, P_secsata[j].neighmac[0], j);
                       skip = 1;
                    }
                    break;
                }

            }

            if (skip == 0 && i != 0) {
                memcpy(P_secsata[last_pos].neighmac, P_secstatus[i].neighmac, sizeof(P_secsata[last_pos].neighmac));
                P_secsata[last_pos].secstatus = P_secstatus[i].secstatus;
                memcpy(P_secsata[last_pos].peermac, P_secstatus[i].peermac, sizeof(P_secsata[last_pos].peermac));
                DBG_INFO("Add new entry P_secstatus[%d].neighmac(%02X) is add to P_secsata[%d].neighbmac = %02X\n", i, P_secstatus[i].neighmac[0], last_pos, P_secsata[last_pos].neighmac[0]);
                last_pos++;
            }


        }

    }

        return last_pos;
}
//---------------------------------------------------------------------------

AMAS_FUNC AMAS_RESULT
AMAS_API  amas_get_secstatus(sec_status **P_secstatus, int *len)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;
    FILE *file = NULL;

    json_object *NeighborListObj = NULL;
    json_object *InterfaceData = NULL;
    json_object *ArrayData1 = NULL;
    json_object *ArrayKeyData = NULL;
    json_object *TLVsData = NULL;
    json_object *TLVData = NULL;
    json_object *subtype = NULL;
    json_object *subtypeVal = NULL;
    json_object *TLVSentry = NULL;
    json_object *TLVentry = NULL;
    json_object *ValueLen = NULL;

    sec_status *Psecstatus = NULL;

    sec_status *Psecdata = NULL;

    int ArrayData1Len = 0;
    int TLVDataLen = 0;
    int k = 0, j = 0;
    int cnt = 0;

    unsigned char OriValue[MAX_VERSION_TEXT_LENGTH + 1]={0};
    int OriValueLen = 0;


    remove(SZ_LLDP_SHOW_OBD_OUTFNAME);
    doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_OBD_OUTFNAME);

    NeighborListObj = json_object_from_file(SZ_LLDP_SHOW_OBD_OUTFNAME);

    DBG_INFO("%s:%d Output neighbor to %s\n", __FUNCTION__, __LINE__, SZ_LLDP_SHOW_OBD_OUTFNAME);
    if (NeighborListObj)
    {
        json_object_object_get_ex(NeighborListObj, "lldp", &InterfaceData);
        if (InterfaceData)
        {
            json_object_object_get_ex(InterfaceData, "interface", &ArrayData1);
            if (ArrayData1)
            {
                if (json_object_get_type(ArrayData1) == json_type_array)
                {
                    ArrayData1Len = json_object_array_length(ArrayData1);

                    Psecstatus = (struct _security_status *) malloc(ArrayData1Len *sizeof(struct _security_status));

                    memset(Psecstatus, 0x00, ArrayData1Len *sizeof(struct _security_status));

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    for (k = 0; k < ArrayData1Len; k++)
                    {
                        TLVSentry = json_object_array_get_idx(ArrayData1, k);

                        json_object_object_foreach(TLVSentry, key, ArrayKeyData)
                        {
                            DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                            if(ArrayKeyData)
                            {
                                json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                                if (TLVsData)
                                {
                                    json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                    if (json_object_get_type(TLVData) == json_type_array)
                                    {
                                        TLVDataLen = json_object_array_length(TLVData);
                                        DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);
                                        for (j = 0; j < TLVDataLen; j++)
                                        {
                                            TLVentry = json_object_array_get_idx(TLVData, j);
                                            json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                            json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                            if (ValueLen) {
                                                OriValueLen = json_object_get_int(ValueLen);
                                                DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                                //OriValue = malloc(OriValueLen * sizeof(char));
                                                memset(OriValue, 0x00, sizeof(OriValue));
                                            }
                                            if (subtype) {
                                                DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                                if(json_object_get_int(subtype) == AMAS_SUBTYPE_SECSTATUS) {
                                                    json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                    if(subtypeVal) {
                                                         STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                         HEXVAL(OriValue,  Psecstatus[k].secstatus, OriValueLen);

                                                    }
                                                }
                                                if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                                    json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                    if(subtypeVal) {
                                                         STR2HEX(Psecstatus[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                                    }
                                                }

                                                if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                                    json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                    if(subtypeVal) {
                                                         STR2HEX(Psecstatus[k].peermac, json_object_get_string(subtypeVal), OriValueLen);
                                                    }
                                                }
                                                DBG_INFO("############################################################\n");
                                                DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Psecstatus[k].neighmac[0], Psecstatus[k].neighmac[1], Psecstatus[k].neighmac[2], Psecstatus[k].neighmac[3], Psecstatus[k].neighmac[4], Psecstatus[k].neighmac[5]);
                                                DBG_INFO("%s:%d  Entry[%d] peer_neighbor MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Psecstatus[k].peermac[0], Psecstatus[k].peermac[1], Psecstatus[k].peermac[2], Psecstatus[k].peermac[3], Psecstatus[k].peermac[4], Psecstatus[k].peermac[5]);
                                                DBG_INFO("%s:%d  Entry[%d] security status = %d\n", __FUNCTION__, __LINE__,k, Psecstatus[k].secstatus);
                                                DBG_INFO("############################################################\n");
                                            }
                                            else
                                                goto amas_get_secstatus_Fail;
                                        }
                                    }
                                    else
                                    {
                                        json_object_object_get_ex(TLVData, "subtype", &subtype);

                                        json_object_object_get_ex(TLVData, "len", &ValueLen);
                                        if (ValueLen) {
                                            OriValueLen = json_object_get_int(ValueLen);
                                            DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                            //OriValue = malloc(OriValueLen * sizeof(char));
                                            memset(OriValue, 0x00, sizeof(OriValue));
                                        }
                                        if (subtype) {
                                            DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_SECSTATUS) {
                                                json_object_object_get_ex(TLVData, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     HEXVAL(OriValue,  Psecstatus[k].secstatus, OriValueLen);
                                                }
                                            }
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                                json_object_object_get_ex(TLVData, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Psecstatus[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                                json_object_object_get_ex(TLVData, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Psecstatus[k].peermac, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }
                                            DBG_INFO("############################################################\n");
                                            DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Psecstatus[k].neighmac[0], Psecstatus[k].neighmac[1], Psecstatus[k].neighmac[2], Psecstatus[k].neighmac[3], Psecstatus[k].neighmac[4], Psecstatus[k].neighmac[5]);
                                            DBG_INFO("%s:%d  Entry[%d] peer_neighbor MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Psecstatus[k].peermac[0], Psecstatus[k].peermac[1], Psecstatus[k].peermac[2], Psecstatus[k].peermac[3], Psecstatus[k].peermac[4], Psecstatus[k].peermac[5]);
                                            DBG_INFO("%s:%d  Entry[%d] security status = %d\n", __FUNCTION__, __LINE__,k, Psecstatus[k].secstatus);
                                            DBG_INFO("############################################################\n");
                                        }
                                        else
                                            goto amas_get_secstatus_Fail;
                                    }
                                }
                            }
                        }

                    }
                }
                else {
                    ArrayData1Len = 1;

                    Psecstatus = (struct _security_status *) malloc(ArrayData1Len *sizeof(struct _security_status));
                    memset(Psecstatus, 0x00, ArrayData1Len *sizeof(struct _security_status));

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    json_object_object_foreach(ArrayData1, key, ArrayKeyData)
                    {
                        DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                        if(ArrayKeyData)
                        {
                            json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                            if (TLVsData)
                            {
                                json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                if (json_object_get_type(TLVData) == json_type_array)
                                {
                                    TLVDataLen = json_object_array_length(TLVData);
                                    DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);
                                    for (j = 0; j < TLVDataLen; j++)
                                    {
                                        TLVentry = json_object_array_get_idx(TLVData, j);
                                        json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                        json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                        if (ValueLen) {
                                            OriValueLen = json_object_get_int(ValueLen);
                                            DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                            //OriValue = malloc(OriValueLen * sizeof(char));
                                            memset(OriValue, 0x00, sizeof(OriValue));
                                        }
                                        if (subtype) {
                                            DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_SECSTATUS) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     HEXVAL(OriValue,  Psecstatus[k].secstatus, OriValueLen);
                                                }
                                            }
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Psecstatus[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Psecstatus[k].peermac, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }
                                    DBG_INFO("############################################################\n");
                                    DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Psecstatus[k].neighmac[0], Psecstatus[k].neighmac[1], Psecstatus[k].neighmac[2], Psecstatus[k].neighmac[3], Psecstatus[k].neighmac[4], Psecstatus[k].neighmac[5]);
                                    DBG_INFO("%s:%d  Entry[%d] peer_neighbor MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Psecstatus[k].peermac[0], Psecstatus[k].peermac[1], Psecstatus[k].peermac[2], Psecstatus[k].peermac[3], Psecstatus[k].peermac[4], Psecstatus[k].peermac[5]);
                                    DBG_INFO("%s:%d  Entry[%d] security status = %d\n", __FUNCTION__, __LINE__,k, Psecstatus[k].secstatus);
                                    DBG_INFO("############################################################\n");
                                        }
                                        else
                                            goto amas_get_secstatus_Fail;
                                    }
                                }
                                else
                                {
                                   json_object_object_get_ex(TLVData, "subtype", &subtype);

                                    json_object_object_get_ex(TLVData, "len", &ValueLen);
                                    if (ValueLen) {
                                        OriValueLen = json_object_get_int(ValueLen);
                                        DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                        memset(OriValue, 0x00, sizeof(OriValue));
                                    }
                                    if (subtype) {
                                        DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_SECSTATUS) {
                                            json_object_object_get_ex(TLVData, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 HEXVAL(OriValue,  Psecstatus[k].secstatus, OriValueLen);
                                            }
                                        }
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                            json_object_object_get_ex(TLVData, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(Psecstatus[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                            json_object_object_get_ex(TLVData, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(Psecstatus[k].peermac, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }
                                        DBG_INFO("############################################################\n");
                                        DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Psecstatus[k].neighmac[0], Psecstatus[k].neighmac[1], Psecstatus[k].neighmac[2], Psecstatus[k].neighmac[3], Psecstatus[k].neighmac[4], Psecstatus[k].neighmac[5]);
                                        DBG_INFO("%s:%d  Entry[%d] peer_neighbor MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Psecstatus[k].peermac[0], Psecstatus[k].peermac[1], Psecstatus[k].peermac[2], Psecstatus[k].peermac[3], Psecstatus[k].peermac[4], Psecstatus[k].peermac[5]);
                                        DBG_INFO("%s:%d  Entry[%d] security status = %d\n", __FUNCTION__, __LINE__,k, Psecstatus[k].secstatus);
                                        DBG_INFO("############################################################\n");
                                    }
                                    else
                                        goto amas_get_secstatus_Fail;
                                }
                            }
                        }
                    }
                }
            }
        }

    }
    if (ArrayData1Len > 0) {
        Psecdata = (struct _security_status *) malloc(ArrayData1Len *sizeof(struct _security_status));
        memset(Psecdata, 0x00, ArrayData1Len *sizeof(struct _security_status));
        cnt = remove_unnecessary_security_status_data(Psecstatus, Psecdata, ArrayData1Len);

        DBG_INFO("Entry count = %u\n", cnt);

        for(k=0; k<cnt; k++) {
            DBG_INFO("Entry(%d) %02X:%02X:%02X:%02X:%02X:%02X %d\n", k, Psecdata[k].neighmac[0],Psecdata[k].neighmac[1],Psecdata[k].neighmac[2],Psecdata[k].neighmac[3],Psecdata[k].neighmac[4],Psecdata[k].neighmac[5],
              Psecdata[k].secstatus);
        }

        if(cnt > 0) {
            *P_secstatus = (struct _security_status *) Psecdata;
        }
        else if (cnt == 0) {
            free(Psecdata);
        }
    }


    if (!IsNULL_PTR(len)) *(len) = cnt;

    if (NeighborListObj)
        json_object_put(NeighborListObj);


    if (Psecstatus)
        free(Psecstatus);

    RETURN_AMAS_RESULT_SUCCESS;

amas_get_secstatus_Fail:
    if (NeighborListObj)
        json_object_put(NeighborListObj);

    if (Psecstatus)
        free(Psecstatus);

        RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_secstatus(
    int status)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (status == 0) {
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_SECSTATUS);
        RETURN_AMAS_RESULT_SUCCESS;
    }

    if ((res = LLDP_NBR_TLV_SET_INT(AMAS_SUBTYPE_SECSTATUS, status)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_secstatus_Fail;
    }

    RETURN_AMAS_RESULT_SUCCESS;

amas_set_secstatus_Fail:

    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
int  remove_unnecessary_keyexchange_data(data_exchange *Pkeychange, data_exchange *Pkeychangedata, int nItem)
{

    unsigned i = 0, last_pos=0;
    int j =0;
    int skip = 0;

    if(Pkeychange==NULL)
        return 0U;

    for(i=0; i<nItem; i++)
    {

        if(isNull(Pkeychange[i].neighmac, sizeof(Pkeychange[i].neighmac)) ||  isNull(Pkeychange[i].data, sizeof(Pkeychange[i].data)))
            continue;

        if (i == 0) {
            memcpy(Pkeychangedata[i].neighmac, Pkeychange[i].neighmac, sizeof(Pkeychangedata[i].neighmac));
            memcpy(Pkeychangedata[i].peermac, Pkeychange[i].peermac, sizeof(Pkeychangedata[i].peermac));
            memcpy(Pkeychangedata[i].data, Pkeychange[i].data, sizeof(Pkeychangedata[i].data));
            Pkeychangedata[i].datalen = Pkeychange[i].datalen;
            memcpy(&Pkeychangedata[i].ifname[0], &Pkeychange[i].ifname[0], sizeof(Pkeychangedata[i].ifname));
            last_pos++;
        }
        else {
            for(j=0; j < nItem; j++)
            {
                 skip = 0;
                 if(!memcmp(Pkeychange[i].neighmac, Pkeychangedata[j].neighmac, sizeof(Pkeychange[i].neighmac)))
                {

                    if(memcmp(Pkeychange[i].data, Pkeychangedata[j].data, sizeof(Pkeychange[i].data))) {
                        DBG_INFO("Pkeychange[%d].data(%d) is different with Pkeychangedata[%d].data(%d).\n", i, Pkeychange[i].data[0], j, Pkeychangedata[j].data[0]);
                        skip = 0;
                    }
                    else {
                       DBG_INFO("Pkeychange[%d].neighmac(%02X) at Pkeychangedata[%d]\n",i, Pkeychangedata[j].neighmac[0], j);
                       skip = 1;
                    }
                    break;
                }

            }

            if (skip == 0 && i != 0) {
                memcpy(Pkeychangedata[last_pos].neighmac, Pkeychange[i].neighmac, sizeof(Pkeychangedata[last_pos].neighmac));
                memcpy(Pkeychangedata[last_pos].data, Pkeychange[i].data, sizeof(Pkeychangedata[last_pos].data));
                memcpy(Pkeychangedata[last_pos].peermac, Pkeychange[i].peermac, sizeof(Pkeychangedata[last_pos].peermac));
                Pkeychangedata[last_pos].datalen = Pkeychange[i].datalen;
                memcpy(&Pkeychangedata[last_pos].ifname[0], &Pkeychange[i].ifname[0], sizeof(Pkeychangedata[last_pos].ifname));
                DBG_INFO("Add new entry Pkeychange[%d].neighmac(%02X) is add to Pkeychangedata[%d].neighbmac = %02X\n", i, Pkeychange[i].neighmac[0], last_pos, Pkeychangedata[last_pos].neighmac[0]);
                last_pos++;
            }


        }

    }

        return last_pos;
}
//---------------------------------------------------------------------------
//AMAS_FUNC AMAS_RESULT
//AMAS_API  amas_get_sessionkey(unsigned char *sessionkey, int *len)
AMAS_FUNC AMAS_RESULT
AMAS_API  amas_get_sessionkey(data_exchange **P_keyexchange, int *len)
{

    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;
    FILE *file = NULL;

    json_object *NeighborListObj = NULL;
    json_object *InterfaceData = NULL;
    json_object *ArrayData1 = NULL;
    json_object *ArrayKeyData = NULL;
    json_object *TLVsData = NULL;
    json_object *TLVData = NULL;
    json_object *subtype = NULL;
    json_object *subtypeVal = NULL;
    json_object *TLVSentry = NULL;
    json_object *TLVentry = NULL;
    json_object *ValueLen = NULL;

    data_exchange *Pkeychange = NULL;

    data_exchange *Pkeychangedata = NULL;

    int ArrayData1Len = 0;
    int TLVDataLen = 0;
    int k = 0, j = 0, q = 0;
    int cnt = 0;

    unsigned char OriValue[MAX_VERSION_TEXT_LENGTH + 1]={0};
    int OriValueLen = 0;


    remove(SZ_LLDP_SHOW_OBD_OUTFNAME);
    doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_OBD_OUTFNAME);

    NeighborListObj = json_object_from_file(SZ_LLDP_SHOW_OBD_OUTFNAME);

    DBG_INFO("%s:%d Output neighbor to %s\n", __FUNCTION__, __LINE__, SZ_LLDP_SHOW_OBD_OUTFNAME);
    if (NeighborListObj)
    {
        json_object_object_get_ex(NeighborListObj, "lldp", &InterfaceData);
        if (InterfaceData)
        {
            json_object_object_get_ex(InterfaceData, "interface", &ArrayData1);
            if (ArrayData1)
            {
                if (json_object_get_type(ArrayData1) == json_type_array)
                {
                    ArrayData1Len = json_object_array_length(ArrayData1);

                    Pkeychange = (struct _data_exchange *) malloc(ArrayData1Len *sizeof(struct _data_exchange));

                    memset(Pkeychange, 0x00, ArrayData1Len *sizeof(struct _data_exchange));

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    for (k = 0; k < ArrayData1Len; k++)
                    {
                        TLVSentry = json_object_array_get_idx(ArrayData1, k);

                        json_object_object_foreach(TLVSentry, key, ArrayKeyData)
                        {
                            DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                            if(ArrayKeyData)
                            {
                                json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                                if (TLVsData)
                                {
                                    json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                    if (json_object_get_type(TLVData) != json_type_array)
                                        goto amas_get_sessionkey_Fail;

                                    memcpy(&Pkeychange[k].ifname[0], key, sizeof(Pkeychange[k].ifname));

                                    TLVDataLen = json_object_array_length(TLVData);
                                    DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);
                                    for (j = 0; j < TLVDataLen; j++)
                                    {
                                        TLVentry = json_object_array_get_idx(TLVData, j);
                                        json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                        json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                        if (ValueLen) {
                                            OriValueLen = json_object_get_int(ValueLen);
                                            DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                            //OriValue = malloc(OriValueLen * sizeof(char));
                                            memset(OriValue, 0x00, sizeof(OriValue));
                                        }
                                        if (subtype)
                                        {
                                            DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_SESSIONKEY) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                    STR2HEX(Pkeychange[k].data, json_object_get_string(subtypeVal), OriValueLen);
                                                    Pkeychange[k].datalen = OriValueLen;
                                                }
                                            }
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Pkeychange[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Pkeychange[k].peermac, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }
                                        }
                                        else
                                            goto amas_get_sessionkey_Fail;
                                    }
                                        DBG_INFO("############################################################\n");
                                        DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Pkeychange[k].neighmac[0], Pkeychange[k].neighmac[1], Pkeychange[k].neighmac[2], Pkeychange[k].neighmac[3], Pkeychange[k].neighmac[4], Pkeychange[k].neighmac[5]);
                                        DBG_INFO("%s:%d  Entry[%d] peer's MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Pkeychange[k].peermac[0], Pkeychange[k].peermac[1], Pkeychange[k].peermac[2], Pkeychange[k].peermac[3], Pkeychange[k].peermac[4], Pkeychange[k].peermac[5]);
                                        DBG_INFO("%s:%d  Entry[%d] SessionKey =", __FUNCTION__,__LINE__, k);
                                        for(q = 0; q < Pkeychange[k].datalen; q++)
                                                DBG_INFO("%02X ", Pkeychange[k].data[q]);
                                        DBG_INFO("\n");
                                        DBG_INFO("%s:%d  Entry[%d] interface = %s\n", __FUNCTION__,__LINE__, k, Pkeychange[k].ifname);
                                        DBG_INFO("############################################################\n");

                                }
                            }
                        }

                    }
                }
                else {
                    ArrayData1Len = 1;

                    Pkeychange = (struct _data_exchange *) malloc(ArrayData1Len *sizeof(struct _data_exchange));
                    memset(Pkeychange, 0x00, ArrayData1Len *sizeof(struct _data_exchange));

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    json_object_object_foreach(ArrayData1, key, ArrayKeyData)
                    {
                        DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                        if(ArrayKeyData)
                        {
                            json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                            if (TLVsData)
                            {
                                json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                if (json_object_get_type(TLVData) != json_type_array)
                                    goto amas_get_sessionkey_Fail;

                                memcpy(&Pkeychange[k].ifname[0], key, sizeof(Pkeychange[k].ifname));

                                TLVDataLen = json_object_array_length(TLVData);
                                DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);
                                for (j = 0; j < TLVDataLen; j++)
                                {
                                    TLVentry = json_object_array_get_idx(TLVData, j);
                                    json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                    json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                    if (ValueLen) {
                                        OriValueLen = json_object_get_int(ValueLen);
                                        DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                        //OriValue = malloc(OriValueLen * sizeof(char));
                                        memset(OriValue, 0x00, sizeof(OriValue));
                                    }
                                    if (subtype) {
                                        DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_SESSIONKEY) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                DBG_INFO("%s:%d json_object_get_string(subtypeVal) = %s\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal));
                                                STR2HEX(Pkeychange[k].data, json_object_get_string(subtypeVal), OriValueLen);
                                                Pkeychange[k].datalen = OriValueLen;
                                            }
                                        }
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                DBG_INFO("%s:%d json_object_get_string(subtypeVal) = %s\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal));
                                                 STR2HEX(Pkeychange[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(Pkeychange[k].peermac, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }
                                    }
                                    else
                                        goto amas_get_sessionkey_Fail;
                                }
                                DBG_INFO("############################################################\n");
                                DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Pkeychange[k].neighmac[0], Pkeychange[k].neighmac[1], Pkeychange[k].neighmac[2], Pkeychange[k].neighmac[3], Pkeychange[k].neighmac[4], Pkeychange[k].neighmac[5]);
                                DBG_INFO("%s:%d  Entry[%d] peer's MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Pkeychange[k].peermac[0], Pkeychange[k].peermac[1], Pkeychange[k].peermac[2], Pkeychange[k].peermac[3], Pkeychange[k].peermac[4], Pkeychange[k].peermac[5]);
                                DBG_INFO("%s:%d  Entry[%d] SessionKey =", __FUNCTION__,__LINE__, k);
                                for(q = 0; q < Pkeychange[k].datalen; q++)
                                        DBG_INFO("%02X ", Pkeychange[k].data[q]);
                                DBG_INFO("\n");
                                DBG_INFO("%s:%d  Entry[%d] key len =", __FUNCTION__,__LINE__, k, Pkeychange[k].datalen);
                                DBG_INFO("%s:%d  Entry[%d] interface = %s\n", __FUNCTION__,__LINE__, k, Pkeychange[k].ifname);
                                DBG_INFO("############################################################\n");
                            }
                        }
                    }
                }
            }
        }

    }
    if (ArrayData1Len > 0) {
        Pkeychangedata = (struct _data_exchange *) malloc(ArrayData1Len *sizeof(struct _data_exchange));
        memset(Pkeychangedata, 0x00, ArrayData1Len *sizeof(struct _data_exchange));
        cnt = remove_unnecessary_keyexchange_data(Pkeychange, Pkeychangedata, ArrayData1Len);

        DBG_INFO("Entry count = %u\n", cnt);

        for(k=0; k<cnt; k++) {
            DBG_INFO("Entry(%d) %02X:%02X:%02X:%02X:%02X:%02X %X\n", k, Pkeychangedata[k].neighmac[0],Pkeychangedata[k].neighmac[1],Pkeychangedata[k].neighmac[2],Pkeychangedata[k].neighmac[3],Pkeychangedata[k].neighmac[4],Pkeychangedata[k].neighmac[5],
              Pkeychangedata[k].data[0]);
        }

        if(cnt > 0) {
            *P_keyexchange = (struct _data_exchange *) Pkeychangedata;
        }
        else if (cnt == 0) {
            free(Pkeychangedata);
        }
    }


    if (!IsNULL_PTR(len)) *(len) = cnt;

    if (NeighborListObj)
        json_object_put(NeighborListObj);


    if (Pkeychange)
        free(Pkeychange);

    RETURN_AMAS_RESULT_SUCCESS;

amas_get_sessionkey_Fail:
    if (NeighborListObj)
        json_object_put(NeighborListObj);

    if (Pkeychange)
        free(Pkeychange);

        RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_sessionkey(
    unsigned char *sessionkey)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if(!memcmp(sessionkey, "none", 4) || !memcmp(sessionkey, "NONE", 4)) {
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_SESSIONKEY);
        RETURN_AMAS_RESULT_SUCCESS;
    }


    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_SESSIONKEY, sessionkey, strlen(sessionkey))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_sessionkey_Fail;
    }


    RETURN_AMAS_RESULT_SUCCESS;

amas_set_sessionkey_Fail:

    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API  amas_get_wifisec(char *type, unsigned char *value, int *len)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;
    FILE *file = NULL;

    json_object *NeighborListObj = NULL;
    json_object *InterfaceData = NULL;
    json_object *ArrayData1 = NULL;
    json_object *ArrayKeyData = NULL;
    json_object *TLVsData = NULL;
    json_object *TLVData = NULL;
    json_object *subtype = NULL;
    json_object *subtypeVal = NULL;
    json_object *TLVSentry = NULL;
    json_object *TLVentry = NULL;
    json_object *ValueLen = NULL;

    int ArrayData1Len = 0;
    int TLVDataLen = 0;
    int k = 0, j = 0, i = 0;
    int inputtype = 0;

    unsigned char *OriValue = NULL;
    int OriValueLen = 0;


    DBG_INFO("%s:%d type = %s\n", __FUNCTION__, __LINE__, type);

    if(!memcmp(type,"ssid", sizeof(type)))
        inputtype = AMAS_SUBTYPE_WIFISSID;
    if(!memcmp(type,"auth", sizeof(type)))
        inputtype = AMAS_SUBTYPE_WIFIAUTHMODE;
    if(!memcmp(type,"crypto", sizeof(type)))
        inputtype = AMAS_SUBTYPE_WIFICRYPTOMODE;
    if(!memcmp(type,"key", sizeof(type)))
        inputtype = AMAS_SUBTYPE_WIFIKEY;

    if(inputtype == 0)
        goto amas_get_wifisec_Fail;


    remove(SZ_LLDP_SHOW_OBD_OUTFNAME);
    doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_OBD_OUTFNAME);

    NeighborListObj = json_object_from_file(SZ_LLDP_SHOW_OBD_OUTFNAME);

    DBG_INFO("%s:%d Output neighbor to %s\n", __FUNCTION__, __LINE__, SZ_LLDP_SHOW_OBD_OUTFNAME);
    if (NeighborListObj)
    {
        json_object_object_get_ex(NeighborListObj, "lldp", &InterfaceData);
        if (InterfaceData)
        {
            json_object_object_get_ex(InterfaceData, "interface", &ArrayData1);
            if (ArrayData1)
            {
                if (json_object_get_type(ArrayData1) == json_type_array)
                {
                    ArrayData1Len = json_object_array_length(ArrayData1);

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    for (k = 0; k < ArrayData1Len; k++)
                    {
                        TLVSentry = json_object_array_get_idx(ArrayData1, k);

                        json_object_object_foreach(TLVSentry, key, ArrayKeyData)
                        {
                            DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                            if(ArrayKeyData)
                            {
                                json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                                if (TLVsData)
                                {
                                    json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                    if (json_object_get_type(TLVData) != json_type_array)
                                        goto amas_get_wifisec_Fail;

                                    TLVDataLen = json_object_array_length(TLVData);

                                    for (j = 0; j < TLVDataLen; j++)
                                    {
                                        TLVentry = json_object_array_get_idx(TLVData, j);
                                        json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                        json_object_object_get_ex(TLVentry, "len", &ValueLen);

                                        if (ValueLen) {
                                            OriValueLen = json_object_get_int(ValueLen);
                                            DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                        }

                                        if (subtype) {
                                            DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));


                                            if(json_object_get_int(subtype) == inputtype) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(value, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                                if (!IsNULL_PTR(len)) *(len) = OriValueLen;
                                                break;
                                            }
                                        }
                                        else
                                            goto amas_get_wifisec_Fail;
                                    }

                                }
                            }
                        }

                    }
                }
                else
                {
                    json_object_object_foreach(ArrayData1, key, ArrayKeyData)
                    {
                        DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                        if(ArrayKeyData)
                        {
                            json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                            if (TLVsData)
                            {
                                json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                if (json_object_get_type(TLVData) != json_type_array)
                                    goto amas_get_wifisec_Fail;

                                TLVDataLen = json_object_array_length(TLVData);

                                for (j = 0; j < TLVDataLen; j++)
                                {
                                    TLVentry = json_object_array_get_idx(TLVData, j);
                                    json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                    json_object_object_get_ex(TLVentry, "len", &ValueLen);

                                    if (ValueLen) {
                                        OriValueLen = json_object_get_int(ValueLen);
                                        DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                    }

                                    if (subtype) {
                                        DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));


                                        if(json_object_get_int(subtype) == inputtype) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(value, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                            if (!IsNULL_PTR(len)) *(len) = OriValueLen;
                                            break;
                                        }
                                    }
                                    else
                                        goto amas_get_wifisec_Fail;
                                }

                            }
                        }
                    }
                }
            }
        }

    }

    if (NeighborListObj)
        json_object_put(NeighborListObj);


    RETURN_AMAS_RESULT_SUCCESS;

amas_get_wifisec_Fail:
    if (NeighborListObj)
        json_object_put(NeighborListObj);

        RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_wifisec(
    char *type, unsigned char *value)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int subtype = 0;

    DBG_INFO("%s:%d type = %s\n", __FUNCTION__, __LINE__, type);

    if(!memcmp(type,"ssid", sizeof(type)))
        subtype = AMAS_SUBTYPE_WIFISSID;
    if(!memcmp(type,"auth", sizeof(type)))
        subtype = AMAS_SUBTYPE_WIFIAUTHMODE;
    if(!memcmp(type,"crypto", sizeof(type)))
        subtype = AMAS_SUBTYPE_WIFICRYPTOMODE;
    if(!memcmp(type,"key", sizeof(type)))
        subtype = AMAS_SUBTYPE_WIFIKEY;

    if(subtype == 0)
        goto amas_set_wifisec_Fail;


    if(!memcmp(value, "none", 4) || !memcmp(value, "NONE", 4)) {
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(subtype);
        RETURN_AMAS_RESULT_SUCCESS;
    }


    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(subtype, value, strlen(value))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_wifisec_Fail;
    }


    RETURN_AMAS_RESULT_SUCCESS;

amas_set_wifisec_Fail:

    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
int  remove_unnecessary_idinfo_data(id_info *Pidinfo, id_info *Pidinfodata, int nItem)
{

    unsigned i = 0, last_pos=0;
    int j =0;
    int skip = 0;

    if(Pidinfo==NULL)
        return 0U;

    for(i=0; i<nItem; i++)
    {

        if(isNull(Pidinfo[i].neighmac, sizeof(Pidinfo[i].neighmac)) ||  Pidinfo[i].obstatus == 0)
            continue;
        if (i == 0) {
            memcpy(Pidinfodata[i].neighmac, Pidinfo[i].neighmac, sizeof(Pidinfodata[i].neighmac));
            memcpy(Pidinfodata[i].id, Pidinfo[i].id, sizeof(Pidinfodata[i].id));
            memcpy(Pidinfodata[i].newremac, Pidinfo[i].newremac, sizeof(Pidinfodata[i].newremac));
            memcpy(Pidinfodata[i].modelname, Pidinfo[i].modelname, sizeof(Pidinfodata[i].modelname));
            memcpy(Pidinfodata[i].tcode, Pidinfo[i].tcode, sizeof(Pidinfodata[i].tcode));
            memcpy(Pidinfodata[i].miscinfo, Pidinfo[i].miscinfo, sizeof(Pidinfodata[i].miscinfo));
            Pidinfodata[i].idlen = Pidinfo[i].idlen;
            Pidinfodata[i].timestamp = Pidinfo[i].timestamp;
            Pidinfodata[i].obstatus = Pidinfo[i].obstatus;
            last_pos++;
        }
        else {
            for(j=0; j < nItem; j++)
            {
                 skip = 0;
                 if(!memcmp(Pidinfo[i].neighmac, Pidinfodata[j].neighmac, sizeof(Pidinfo[i].neighmac)))
                {
                    if(Pidinfo[i].obstatus != Pidinfodata[j].obstatus) {
                        DBG_INFO("Pidinfo[%d].obstatus(%d) is different with Pidinfodata[%d].obstatus(%d).\n", i, Pidinfo[i].obstatus, j, Pidinfodata[j].obstatus);
                        skip = 0;
                    }
                    else {
                       DBG_INFO("Pidinfo[%d].neighmac(%02X) at Pidinfodata[%d]\n",i, Pidinfodata[j].neighmac[0], j);
                       skip = 1;
                    }
                    break;
                }

            }

            if (skip == 0 && i != 0) {
                memcpy(Pidinfodata[last_pos].neighmac, Pidinfo[i].neighmac, sizeof(Pidinfodata[last_pos].neighmac));
                memcpy(Pidinfodata[last_pos].id, Pidinfo[i].id, sizeof(Pidinfodata[last_pos].id));
                memcpy(Pidinfodata[last_pos].newremac, Pidinfo[i].newremac, sizeof(Pidinfodata[last_pos].newremac));
                memcpy(Pidinfodata[last_pos].modelname, Pidinfo[i].modelname, sizeof(Pidinfodata[i].modelname));
                memcpy(Pidinfodata[last_pos].tcode, Pidinfo[i].tcode, sizeof(Pidinfodata[i].tcode));
                memcpy(Pidinfodata[last_pos].miscinfo, Pidinfo[i].miscinfo, sizeof(Pidinfodata[i].miscinfo));
                Pidinfodata[last_pos].idlen = Pidinfo[i].idlen;
                Pidinfodata[last_pos].timestamp = Pidinfo[i].timestamp;
                Pidinfodata[last_pos].obstatus = Pidinfo[i].obstatus;
                DBG_INFO("Add new entry Pidinfo[%d].neighmac(%02X) is add to Pidinfodata[%d].neighbmac = %02X\n", i, Pidinfo[i].neighmac[0], last_pos, Pidinfodata[last_pos].neighmac[0]);
                last_pos++;
            }
        }
    }
    return last_pos;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API  amas_get_obdinfo(id_info **P_idinfo, int *len)
{

    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;
    FILE *file = NULL;

    json_object *NeighborListObj = NULL;
    json_object *InterfaceData = NULL;
    json_object *ArrayData1 = NULL;
    json_object *ArrayKeyData = NULL;
    json_object *TLVsData = NULL;
    json_object *TLVData = NULL;
    json_object *subtype = NULL;
    json_object *subtypeVal = NULL;
    json_object *TLVSentry = NULL;
    json_object *TLVentry = NULL;
    json_object *ValueLen = NULL;

    id_info *Pidinfo = NULL;

    id_info *Pidinfodata = NULL;

    int ArrayData1Len = 0;
    int TLVDataLen = 0;
    int k = 0, j = 0, q =0;
    int cnt = 0;

    unsigned char OriValue[MAX_VERSION_TEXT_LENGTH + 1]={0};
    int OriValueLen = 0;

    remove(SZ_LLDP_SHOW_OBD_OUTFNAME);
    doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_OBD_OUTFNAME);

    NeighborListObj = json_object_from_file(SZ_LLDP_SHOW_OBD_OUTFNAME);

    DBG_INFO("%s:%d Output neighbor to %s\n", __FUNCTION__, __LINE__, SZ_LLDP_SHOW_OBD_OUTFNAME);
    if (NeighborListObj)
    {
        json_object_object_get_ex(NeighborListObj, "lldp", &InterfaceData);
        if (InterfaceData)
        {
            json_object_object_get_ex(InterfaceData, "interface", &ArrayData1);
            if (ArrayData1)
            {
                if (json_object_get_type(ArrayData1) == json_type_array)
                {
                    ArrayData1Len = json_object_array_length(ArrayData1);

                    Pidinfo = (struct _id_info *) malloc(ArrayData1Len *sizeof(struct _id_info));

                    memset(Pidinfo, 0x00, ArrayData1Len *sizeof(struct _id_info));

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    for (k = 0; k < ArrayData1Len; k++)
                    {
                        TLVSentry = json_object_array_get_idx(ArrayData1, k);

                        json_object_object_foreach(TLVSentry, key, ArrayKeyData)
                        {
                            DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                            if(ArrayKeyData)
                            {
                                json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                                if (TLVsData)
                                {
                                    json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                    if (json_object_get_type(TLVData) != json_type_array)
                                        goto amas_get_obd_Fail;

                                    TLVDataLen = json_object_array_length(TLVData);
                                    DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);
                                    for (j = 0; j < TLVDataLen; j++)
                                    {
                                        TLVentry = json_object_array_get_idx(TLVData, j);
                                        json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                        json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                        if (ValueLen) {
                                            OriValueLen = json_object_get_int(ValueLen);
                                            DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                            //OriValue = malloc(OriValueLen * sizeof(char));
                                            memset(OriValue, 0x00, sizeof(OriValue));
                                        }
                                        if (subtype)
                                        {
                                            DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_GROUP) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                    STR2HEX(Pidinfo[k].id, json_object_get_string(subtypeVal), OriValueLen);
                                                    Pidinfo[k].idlen = OriValueLen;
                                                }
                                            }
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Pidinfo[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                    DBG_INFO("%s:%d json_object_get_string(subtypeVal) = %s\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal));
                                                     STR2HEX(Pidinfo[k].newremac, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_OBSTATUS) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     HEXVAL(OriValue,  Pidinfo[k].obstatus, OriValueLen);
                                                }
                                            }
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_MODELNAME) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     ASCII2STR(OriValue,  Pidinfo[k].modelname, OriValueLen);
                                                }
                                            }
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_TCODE) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     ASCII2STR(OriValue,  Pidinfo[k].tcode, OriValueLen);
                                                }
                                            }
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_MISC_INFO) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(Pidinfo[k].miscinfo, json_object_get_string(subtypeVal), OriValueLen);
                                                }
                                            }

                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_TIMESTAMP) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                     STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                     HEXVAL(OriValue,  Pidinfo[k].timestamp, OriValueLen);

                                                }
                                            }
                                        }
                                        else
                                            goto amas_get_obd_Fail;

                                    }
                                    DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Pidinfo[k].neighmac[0], Pidinfo[k].neighmac[1], Pidinfo[k].neighmac[2], Pidinfo[k].neighmac[3], Pidinfo[k].neighmac[4], Pidinfo[k].neighmac[5]);
                                    DBG_INFO("%s:%d  Entry[%d] id len =%d", __FUNCTION__,__LINE__,  Pidinfo[k].idlen);
                                    DBG_INFO("%s:%d  Entry[%d] id =", __FUNCTION__,__LINE__, k);
                                    for(q = 0; q < Pidinfo[k].idlen; q++)
                                        DBG_INFO("%02X ", Pidinfo[k].id[q]);
                                    DBG_INFO("\n");
                                    DBG_INFO("%s:%d  Entry[%d] newremac = %02X:%02X:%02X:%02X:%02X:%02X", __FUNCTION__,__LINE__,  k, Pidinfo[k].newremac[0], Pidinfo[k].newremac[1], Pidinfo[k].newremac[2], Pidinfo[k].newremac[3], Pidinfo[k].newremac[4], Pidinfo[k].newremac[5]);
                                    DBG_INFO("%s:%d  Entry[%d] ob status = %d", __FUNCTION__, __LINE__,k, Pidinfo[k].obstatus);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Timestamp = %X", __FUNCTION__, __LINE__,k, Pidinfo[k].timestamp);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Model Name = %s", __FUNCTION__, __LINE__,k, Pidinfo[k].modelname);
                                    DBG_INFO("%s:%d  Entry[%d] ob status Tcode = %s", __FUNCTION__, __LINE__,k, Pidinfo[k].tcode);
                                    DBG_INFO("%s:%d  Entry[%d] misc info =", __FUNCTION__,__LINE__, k);
                                    for(q = 0; q < sizeof(Pidinfo[k].miscinfo); q++) {
                                        if (Pidinfo[k].miscinfo[q] == '\0') break;
                                        DBG_INFO("%02X ", Pidinfo[k].miscinfo[q]);
                                    }
                                    DBG_INFO("\n");

                                }
                            }
                        }

                    }
                }
                else {
                    ArrayData1Len = 1;

                    Pidinfo = (struct _id_info *) malloc(ArrayData1Len *sizeof(struct _id_info));
                    memset(Pidinfo, 0x00, ArrayData1Len *sizeof(struct _id_info));

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    json_object_object_foreach(ArrayData1, key, ArrayKeyData)
                    {
                        DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                        if(ArrayKeyData)
                        {
                            json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                            if (TLVsData)
                            {
                                json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                if (json_object_get_type(TLVData) != json_type_array)
                                    goto amas_get_obd_Fail;

                                TLVDataLen = json_object_array_length(TLVData);
                                DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);
                                for (j = 0; j < TLVDataLen; j++)
                                {
                                    TLVentry = json_object_array_get_idx(TLVData, j);
                                    json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                    json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                    if (ValueLen) {
                                        OriValueLen = json_object_get_int(ValueLen);
                                        DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                        //OriValue = malloc(OriValueLen * sizeof(char));
                                        memset(OriValue, 0x00, sizeof(OriValue));
                                    }
                                    if (subtype) {
                                        DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_GROUP) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                DBG_INFO("%s:%d json_object_get_string(subtypeVal) = %s\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal));
                                                STR2HEX(Pidinfo[k].id, json_object_get_string(subtypeVal), OriValueLen);
                                                Pidinfo[k].idlen = OriValueLen;
                                            }
                                        }
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_DEVMAC) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                DBG_INFO("%s:%d json_object_get_string(subtypeVal) = %s\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal));
                                                 STR2HEX(Pidinfo[k].neighmac, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_PEERMAC) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                DBG_INFO("%s:%d json_object_get_string(subtypeVal) = %s\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal));
                                                 STR2HEX(Pidinfo[k].newremac, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_OBSTATUS) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 HEXVAL(OriValue,  Pidinfo[k].obstatus, OriValueLen);
                                            }
                                        }
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_MODELNAME) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 ASCII2STR(OriValue,  Pidinfo[k].modelname, OriValueLen);
                                            }
                                        }
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_TCODE) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 ASCII2STR(OriValue,  Pidinfo[k].tcode, OriValueLen);
                                            }
                                        }
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_MISC_INFO) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(Pidinfo[k].miscinfo, json_object_get_string(subtypeVal), OriValueLen);
                                            }
                                        }

                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_TIMESTAMP) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                 HEXVAL(OriValue,  Pidinfo[k].timestamp, OriValueLen);

                                            }
                                        }
                                    }
                                    else
                                        goto amas_get_obd_Fail;
                                }
                                DBG_INFO("############################################################\n");
                                DBG_INFO("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, Pidinfo[k].neighmac[0], Pidinfo[k].neighmac[1], Pidinfo[k].neighmac[2], Pidinfo[k].neighmac[3], Pidinfo[k].neighmac[4], Pidinfo[k].neighmac[5]);
                                DBG_INFO("%s:%d  Entry[%d] id len =%d", __FUNCTION__,__LINE__,  Pidinfo[k].idlen);
                                DBG_INFO("%s:%d  Entry[%d] id =", __FUNCTION__,__LINE__, k);
                                for(q = 0; q < Pidinfo[k].idlen; q++)
                                    DBG_INFO("%02X ", Pidinfo[k].id[q]);
                                DBG_INFO("\n");
                                DBG_INFO("%s:%d  Entry[%d] newremac = %02X:%02X:%02X:%02X:%02X:%02X", __FUNCTION__,__LINE__,  k, Pidinfo[k].newremac[0], Pidinfo[k].newremac[1], Pidinfo[k].newremac[2], Pidinfo[k].newremac[3], Pidinfo[k].newremac[4], Pidinfo[k].newremac[5]);
                                DBG_INFO("%s:%d  Entry[%d] ob status = %d", __FUNCTION__, __LINE__,k, Pidinfo[k].obstatus);
                                DBG_INFO("%s:%d  Entry[%d] ob status Timestamp = %X", __FUNCTION__, __LINE__,k, Pidinfo[k].timestamp);
                                DBG_INFO("%s:%d  Entry[%d] ob status Model Name = %s", __FUNCTION__, __LINE__,k, Pidinfo[k].modelname);
                                DBG_INFO("%s:%d  Entry[%d] ob status Tcode = %s", __FUNCTION__, __LINE__,k, Pidinfo[k].tcode);
                                DBG_INFO("%s:%d  Entry[%d] misc info =", __FUNCTION__,__LINE__, k);
                                for(q = 0; q < sizeof(Pidinfo[k].miscinfo); q++) {
                                    if (Pidinfo[k].miscinfo[q] == '\0') break;
                                    DBG_INFO("%02X ", Pidinfo[k].miscinfo[q]);
                                }
                                DBG_INFO("\n");
                                DBG_INFO("\n");
                                DBG_INFO("############################################################\n");
                            }
                        }
                    }
                }
            }
        }

    }
    if (ArrayData1Len > 0) {
        Pidinfodata = (struct _id_info *) malloc(ArrayData1Len *sizeof(struct _id_info));
        memset(Pidinfodata, 0x00, ArrayData1Len *sizeof(struct _id_info));
        cnt = remove_unnecessary_idinfo_data(Pidinfo, Pidinfodata, ArrayData1Len);

        DBG_INFO("Entry count = %u\n", cnt);

        for(k=0; k<cnt; k++) {
            DBG_INFO("Entry(%d) %02X:%02X:%02X:%02X:%02X:%02X %X\n", k, Pidinfodata[k].neighmac[0],Pidinfodata[k].neighmac[1],Pidinfodata[k].neighmac[2],Pidinfodata[k].neighmac[3],Pidinfodata[k].neighmac[4],Pidinfodata[k].neighmac[5],
              Pidinfodata[k].id[0]);
        }

        if(cnt > 0) {
            *P_idinfo = (struct _id_info *) Pidinfodata;
        }
        else if (cnt == 0) {
            free(Pidinfodata);
        }
    }


    if (!IsNULL_PTR(len)) *(len) = cnt;

    if (NeighborListObj)
        json_object_put(NeighborListObj);


    if (Pidinfo)
        free(Pidinfo);

    RETURN_AMAS_RESULT_SUCCESS;

amas_get_obd_Fail:
    if (NeighborListObj)
        json_object_put(NeighborListObj);

    if (Pidinfo)
        free(Pidinfo);

        RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API  amas_get_group(unsigned char *group, int *len)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;
    FILE *file = NULL;

    json_object *NeighborListObj = NULL;
    json_object *InterfaceData = NULL;
    json_object *ArrayData1 = NULL;
    json_object *ArrayKeyData = NULL;
    json_object *TLVsData = NULL;
    json_object *TLVData = NULL;
    json_object *subtype = NULL;
    json_object *subtypeVal = NULL;
    json_object *TLVSentry = NULL;
    json_object *TLVentry = NULL;
    json_object *ValueLen = NULL;

    int ArrayData1Len = 0;
    int TLVDataLen = 0;
    int k = 0, j = 0, i =0;

    unsigned char temp[7]={0};

    //unsigned char *OriValue = NULL;
    int OriValueLen = 0;
    remove(SZ_LLDP_SHOW_OBD_OUTFNAME);
    doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_OBD_OUTFNAME);

    NeighborListObj = json_object_from_file(SZ_LLDP_SHOW_OBD_OUTFNAME);

    DBG_INFO("%s:%d Output neighbor to %s\n", __FUNCTION__, __LINE__, SZ_LLDP_SHOW_OBD_OUTFNAME);
    if (NeighborListObj)
    {
        json_object_object_get_ex(NeighborListObj, "lldp", &InterfaceData);
        if (InterfaceData)
        {
            json_object_object_get_ex(InterfaceData, "interface", &ArrayData1);
            if (ArrayData1)
            {

                if (json_object_get_type(ArrayData1) == json_type_array)
                {
                    ArrayData1Len = json_object_array_length(ArrayData1);

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    for (k = 0; k < ArrayData1Len; k++)
                    {
                        TLVSentry = json_object_array_get_idx(ArrayData1, k);

                        json_object_object_foreach(TLVSentry, key, ArrayKeyData)
                        {
                            DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                            if(ArrayKeyData)
                            {
                                json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                                if (TLVsData)
                                {
                                    json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                    if (json_object_get_type(TLVData) != json_type_array)
                                        goto amas_get_group_Fail;

                                    TLVDataLen = json_object_array_length(TLVData);

                                    for (j = 0; j < TLVDataLen; j++)
                                    {
                                        TLVentry = json_object_array_get_idx(TLVData, j);
                                        json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                        json_object_object_get_ex(TLVentry, "len", &ValueLen);

                                        if (ValueLen) {
                                            OriValueLen = json_object_get_int(ValueLen);
                                        }

                                        if (subtype) {
                                            DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));


                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_GROUP) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                    STR2HEX(group, json_object_get_string(subtypeVal), OriValueLen);
                                                    if (!IsNULL_PTR(len)) *(len) = OriValueLen;

                                                }
                                            }

                                            DBG_INFO("############################################################\n");
                                            DBG_INFO("Group is");
                                            for (i = 0; i< OriValueLen; i++)
                                                DBG_INFO("%02X ", group[i]);
                                            DBG_INFO("############################################################\n");
                                        }
                                        else
                                            goto amas_get_group_Fail;
                                    }

                                }
                            }
                        }

                    }
                }
                else
                {
                    ArrayData1Len = 1;
                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);
                    json_object_object_foreach(ArrayData1, key, ArrayKeyData)
                    {
                        DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                        if(ArrayKeyData)
                        {
                            json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                            if (TLVsData)
                            {
                                json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                if (json_object_get_type(TLVData) != json_type_array)
                                    goto amas_get_group_Fail;

                                TLVDataLen = json_object_array_length(TLVData);
                                DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);

                                for (j = 0; j < TLVDataLen; j++)
                                {
                                    TLVentry = json_object_array_get_idx(TLVData, j);
                                    json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                    json_object_object_get_ex(TLVentry, "len", &ValueLen);

                                    if (ValueLen) {
                                        OriValueLen = json_object_get_int(ValueLen);
                                        DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);

                                    }

                                    if (subtype) {
                                        DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));


                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_GROUP) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                 DBG_INFO("%s:%d macaddr = (%s) OriValueLen = (%d)\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal), OriValueLen);
                                                 STR2HEX(group, json_object_get_string(subtypeVal), OriValueLen);
                                                if (!IsNULL_PTR(len)) *(len) = OriValueLen;
                                            }
                                        }

                                    DBG_INFO("############################################################\n");
                                    DBG_INFO("Group is");
                                    for (i = 0; i< OriValueLen; i++)
                                        DBG_INFO("%02X ", group[i]);
                                    DBG_INFO("############################################################\n");
                                    }
                                    else
                                        goto amas_get_group_Fail;
                                }

                            }
                        }
                    }

                }
            }
        }

    }

    if (NeighborListObj)
        json_object_put(NeighborListObj);


    RETURN_AMAS_RESULT_SUCCESS;

amas_get_group_Fail:
    if (NeighborListObj)
        json_object_put(NeighborListObj);

        RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_group(
    unsigned char *group)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if(!memcmp(group, "none", 4) || !memcmp(group, "NONE", 4)) {
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_GROUP);
        RETURN_AMAS_RESULT_SUCCESS;
    }


    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_GROUP, group, strlen(group))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_group_Fail;
    }


    RETURN_AMAS_RESULT_SUCCESS;

amas_set_group_Fail:

    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_get_rssi_score(
    char *ifname,
    int bandindex,
    int capability5g,
    char *ifmac,
    int *rssi_score)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;

    if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_rssi_score_Fail;
    }

    if (IsNULL_PTR(rssi_score))
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_rssi_score_Fail;
    }

#if defined(USE_LLDP_CTRL)
    v = lldp_get_rssi_score(ifname, ifmac, &res);
#endif	/* USE_LLDP_CTRL */

    if (res != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_get_rssi_score_Fail;
    }
    if (!IsNULL_PTR(rssi_score)) *(rssi_score) = v;
    RETURN_AMAS_RESULT_SUCCESS;

amas_get_rssi_score_Fail:
    if (!IsNULL_PTR(rssi_score)) *(rssi_score) = 0;
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_rssi_score(
    int rssi_score)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    char *vsie_id = NULL;
    size_t vsie_id_size = 0;
    int ts = time((time_t *)NULL);

    vsie_id = gen_vsie_id(ts, &vsie_id_size);
    if (IsNULL_PTR(vsie_id))
    {
        SET_ERROR_CODE(AMAS_RESULT_GEN_VSIEID_FAILED);
        goto amas_set_rssi_score_Fail;
    }

    if (vsie_id_size != (MAX_VSIEID_LENGTH*2))
    {
        SET_ERROR_CODE(AMAS_RESULT_GEN_VSIEID_FAILED);
        goto amas_set_rssi_score_Fail;
    }

#if defined(USE_LLDP_CTRL)
    if ((res = lldp_set_rssi_score(vsie_id, vsie_id_size, rssi_score)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_rssi_score_Fail;
    }
#else

    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_ID, vsie_id, vsie_id_size)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_rssi_score_Fail;
    }

    if ((res = LLDP_NBR_TLV_SET_INT(AMAS_SUBTYPE_RSSI_SCORE, rssi_score)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_rssi_score_Fail;
    }
#endif	/* USE_LLDP_CTRL */

    MFREE(vsie_id);
    RETURN_AMAS_RESULT_SUCCESS;

amas_set_rssi_score_Fail:
    if (!IsNULL_PTR(vsie_id)) MFREE(vsie_id);
    RETURN_AMAS_RESULT_FAILED;
}


AMAS_FUNC void
AMAS_API amas_set_timeout(
    int rtime, int ctimeout, int ttimeout)
{
    reboot_time = rtime;
    connection_timeout = ctimeout;
    traffic_timeout = ttimeout;
    return;
}


//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_get_wifi_lastbyte(
    char *ifname,
    int bandindex,
    int capability5g,
    char *ifmac,
    char *wifi_lastbyte,
    int wifi_lastbyte_len)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int ret = 0;
    char buf[64] = {0};

    if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_wifi_lastbyte_Fail;
    }

    if (IsNULL_PTR(wifi_lastbyte) || wifi_lastbyte_len == 0)
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_wifi_lastbyte_Fail;
    }

#if defined(USE_LLDP_CTRL)
    ret = lldp_get_wifi_lastbyte(ifname, ifmac, &buf[0], sizeof(buf), &res);
#endif  /* USE_LLDP_CTRL */

    if (res != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_get_wifi_lastbyte_Fail;
    }
    if (strlen(buf)) strlcpy(wifi_lastbyte, buf, wifi_lastbyte_len);
    RETURN_AMAS_RESULT_SUCCESS;

amas_get_wifi_lastbyte_Fail:
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_wifi_lastbyte(
    unsigned char *input_wifi_lastbyte)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    char *vsie_id = NULL;
    size_t vsie_id_size = 0;
    int ts = time((time_t *)NULL);
    unsigned char wifi_lastbyte[18]={0};
    int chkval = 0;
    chkval = cal_colon(input_wifi_lastbyte);
    STR2HEX(wifi_lastbyte, input_wifi_lastbyte, chkval);

    DBG_INFO("wifi_lastbyte  = %02X%02X%02X%02X%02X%02X%02X%02X", wifi_lastbyte[0], wifi_lastbyte[1], wifi_lastbyte[2], wifi_lastbyte[3], wifi_lastbyte[4], wifi_lastbyte[5], wifi_lastbyte[6], wifi_lastbyte[7]);


#if defined(USE_LLDP_CTRL)
    if ((res = lldp_set_wifi_lastbyte(vsie_id, vsie_id_size, wifi_lastbyte, chkval)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_wifi_lastbyte_Fail;
    }
#else
    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_WIFI_LASTBYTE, wifi_lastbyte, strlen(wifi_lastbyte))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_wifi_lastbyte_Fail;
    }
#endif  /* USE_LLDP_CTRL */

    MFREE(vsie_id);
    RETURN_AMAS_RESULT_SUCCESS;

amas_set_wifi_lastbyte_Fail:
    if (!IsNULL_PTR(vsie_id)) MFREE(vsie_id);
    RETURN_AMAS_RESULT_FAILED;
}

/**
 * @brief Get destination ethernet port role.
 *
 */
AMAS_FUNC AMAS_RESULT
AMAS_API amas_get_dest_eth_role(
    char *ifname,
    int *eth_role)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;

    if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_dest_eth_role_Fail;
    }

    if (IsNULL_PTR(eth_role))
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_dest_eth_role_Fail;
    }

#if defined(USE_LLDP_CTRL)
    v = lldp_get_dest_eth_role(ifname, &res);
#endif  /* USE_LLDP_CTRL */

    printf("[%s][%d] v = %d\n", __FUNCTION__, __LINE__, v);

    if (res != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_get_dest_eth_role_Fail;
    }
    if (!IsNULL_PTR(eth_role)) *(eth_role) = v;
    RETURN_AMAS_RESULT_SUCCESS;

amas_get_dest_eth_role_Fail:
    if (!IsNULL_PTR(eth_role)) *(eth_role) = 0;
    RETURN_AMAS_RESULT_FAILED;
}

/**
 * @brief Set ethernet port role.
 *
 */
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_eth_role(
    char *input_eth_role)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    char *vsie_id = NULL;
    size_t vsie_id_size = 0;
    int ts = time((time_t *)NULL);
    char tmp[64] = {};

#if defined(USE_LLDP_CTRL)
    if ((res = lldp_set_eth_role(vsie_id, vsie_id_size, input_eth_role)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_eth_role_Fail;
    }
#else
    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_ETH_ROLE, input_eth_role, strlen(input_eth_role))) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_eth_role_Fail;
    }
#endif

    MFREE(vsie_id);
    RETURN_AMAS_RESULT_SUCCESS;

amas_set_eth_role_Fail:
    if (!IsNULL_PTR(vsie_id)) MFREE(vsie_id);
    RETURN_AMAS_RESULT_FAILED;
}

#if defined(RTCONFIG_PRELINK)
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API  amas_gen_hash_bundle_key(unsigned char *key)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    char *hash_bundle_key = NULL;
    size_t hash_bundle_key_size = 0;
    int ts = time((time_t *)NULL);

    hash_bundle_key = gen_hash_bundle_key(ts, &hash_bundle_key_size);
    if (IsNULL_PTR(hash_bundle_key))
    {
        SET_ERROR_CODE(AMAS_RESULT_GEN_HASH_BUNDLE_KEY_FAILED);
        goto amas_gen_hash_bundle_key_Fail;
    }

    if (hash_bundle_key_size != (MAX_HASH_BUNDLE_KEY_LEN*2))
    {
        SET_ERROR_CODE(AMAS_RESULT_GEN_HASH_BUNDLE_KEY_FAILED);
        goto amas_gen_hash_bundle_key_Fail;
    }

    str2hex_x(hash_bundle_key, key);
    MFREE(hash_bundle_key);
    RETURN_AMAS_RESULT_SUCCESS;

amas_gen_hash_bundle_key_Fail:
    if (!IsNULL_PTR(hash_bundle_key)) MFREE(hash_bundle_key);
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API  amas_verify_hash_bundle_key(unsigned char *key, int *result)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    char *hash_bundle_key = NULL;
    size_t hash_bundle_key_size = 0;
    char hash_bundle_key_hex[MAX_HASH_BUNDLE_KEY_LEN];
    int ts = 0;

    *result = 0;
    ts = key[MAX_HASH_BUNDLE_KEY_LEN - sizeof(int)] << 24 | key[MAX_HASH_BUNDLE_KEY_LEN - sizeof(int) + 1] << 16 |
        key[MAX_HASH_BUNDLE_KEY_LEN - sizeof(int) + 2] << 8 | key[MAX_HASH_BUNDLE_KEY_LEN - sizeof(int) + 3];

    hash_bundle_key = gen_hash_bundle_key(ts, &hash_bundle_key_size);
    if (IsNULL_PTR(hash_bundle_key))
    {
        SET_ERROR_CODE(AMAS_RESULT_VERIFY_HASH_BUNDLE_KEY_FAILED);
        goto amas_verify_hash_bundle_key_Fail;
    }

    if (hash_bundle_key_size != (MAX_HASH_BUNDLE_KEY_LEN*2))
    {
        SET_ERROR_CODE(AMAS_RESULT_VERIFY_HASH_BUNDLE_KEY_FAILED);
        goto amas_verify_hash_bundle_key_Fail;
    }

    str2hex_x(hash_bundle_key, hash_bundle_key_hex);

    if (memcmp((unsigned char *)&key[0], (unsigned char *)&hash_bundle_key_hex[0], MAX_HASH_BUNDLE_KEY_LEN) != 0)
    {
        SET_ERROR_CODE(AMAS_RESULT_VERIFY_HASH_BUNDLE_KEY_FAILED);
        goto amas_verify_hash_bundle_key_Fail;
    }

    *result = 1;
    MFREE(hash_bundle_key);
    RETURN_AMAS_RESULT_SUCCESS;

amas_verify_hash_bundle_key_Fail:
    if (!IsNULL_PTR(hash_bundle_key)) MFREE(hash_bundle_key);
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_hash_bundle_key(int reset)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    unsigned char hash_bundle_key[MAX_HASH_BUNDLE_KEY_LEN * 2 + 1];
    size_t hash_bundle_key_size = MAX_HASH_BUNDLE_KEY_LEN * 2;

    if (reset) {
        LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(AMAS_SUBTYPE_HASH_BUNDLE_KEY);
        RETURN_AMAS_RESULT_SUCCESS;
    }

    if (nvram_get("amas_hashbdlkey") && strlen(nvram_safe_get("amas_hashbdlkey"))) {
        memset(hash_bundle_key, 0, sizeof(hash_bundle_key));
        strlcpy(hash_bundle_key, nvram_safe_get("amas_hashbdlkey"), sizeof(hash_bundle_key));
        if (strlen(hash_bundle_key)  != (MAX_HASH_BUNDLE_KEY_LEN * 2)) {
            SET_ERROR_CODE(AMAS_RESULT_SET_HASH_BUNDLE_KEY_FAILED);
            goto amas_set_hash_bundle_key_Fail;
        }
    }
    else
    {
        SET_ERROR_CODE(AMAS_RESULT_SET_HASH_BUNDLE_KEY_FAILED);
        goto amas_set_hash_bundle_key_Fail;
    }

    if ((res = LLDP_NBR_TLV_SET_HEX_BUFFER(AMAS_SUBTYPE_HASH_BUNDLE_KEY, hash_bundle_key, hash_bundle_key_size)) != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_set_hash_bundle_key_Fail;
    }

    RETURN_AMAS_RESULT_SUCCESS;

amas_set_hash_bundle_key_Fail:
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_gen_default_backhaul_security(char *ssid, int ssid_len, char *psk, int psk_len)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (gen_default_backhaul_security(ssid, ssid_len, psk, psk_len) == 0) {
        SET_ERROR_CODE(AMAS_RESULT_GEN_DEF_BACKHAUL_WIFI_SECURITY_FAILED);
        goto amas_gen_default_backhaul_security_Fail;
    }

    RETURN_AMAS_RESULT_SUCCESS;

amas_gen_default_backhaul_security_Fail:
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_verify_default_backhaul_security(char *ssid, char *psk, int *result)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    char ssid_tmp[33], psk_tmp[33];

    *result = 0;

    if (gen_default_backhaul_security(ssid_tmp, sizeof(ssid_tmp), psk_tmp, sizeof(psk_tmp)) == 0) {
        SET_ERROR_CODE(AMAS_RESULT_GEN_DEF_BACKHAUL_WIFI_SECURITY_FAILED);
        goto amas_gen_default_backhaul_security_Fail;
    }

    DBG_INFO("ssid (%s), ssid_tmp (%s)", ssid, ssid_tmp);
    DBG_INFO("psk (%s), psk_tmp (%s)", psk, psk_tmp);

    if (strcmp(ssid, ssid_tmp) == 0 && strcmp(psk, psk_tmp) == 0) {
        DBG_INFO("default backhaul security is same");
        *result = 1;
    }
    RETURN_AMAS_RESULT_SUCCESS;

amas_gen_default_backhaul_security_Fail:
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
int  remove_unnecessary_bundle_key(bundle_key *Pbundlekey, bundle_key *Pbundlekeydata, int nItem)
{
    unsigned i = 0, last_pos=0;
    int j =0;
    int skip = 0;

    if(Pbundlekey==NULL)
        return 0U;

    for(i=0; i<nItem; i++)
    {
        if (Pbundlekey[i].bundlekeylen == 0)
            continue;

        if (Pbundlekey[i].cost < 0)
            continue;

        if (i == 0) {
            memcpy(Pbundlekeydata[i].bundlekey, Pbundlekey[i].bundlekey, sizeof(Pbundlekeydata[i].bundlekey));
            Pbundlekeydata[i].bundlekeylen = Pbundlekey[i].bundlekeylen;
            Pbundlekeydata[i].cost = Pbundlekey[i].cost;
            last_pos++;
        }
        else {
            for(j=0; j < nItem; j++)
            {
                skip = 0;
                if(!memcmp(Pbundlekey[i].bundlekey, Pbundlekeydata[j].bundlekey, sizeof(Pbundlekey[i].bundlekey)))
                {
                    DBG_INFO("Pbundlekey[%d].bundlekey at Pbundlekeydata[%d]\n",i, j);
                    skip = 1;
                    break;
                }
            }

            if (skip == 0 && i != 0) {
                memcpy(Pbundlekeydata[last_pos].bundlekey, Pbundlekey[i].bundlekey, sizeof(Pbundlekeydata[i].bundlekey));
                Pbundlekeydata[last_pos].bundlekeylen = Pbundlekey[i].bundlekeylen;
                Pbundlekeydata[last_pos].cost = Pbundlekey[i].cost;
                DBG_INFO("Add new entry Pbundlekey[%d].bundlekey is add to Pbundlekeydata[%d].bundlekey\n", i, last_pos);
                last_pos++;
            }
        }
    }
    return last_pos;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API  amas_get_bundle_key(bundle_key **P_bundlekey, int *len)
{

    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;
    FILE *file = NULL;

    json_object *NeighborListObj = NULL;
    json_object *InterfaceData = NULL;
    json_object *ArrayData1 = NULL;
    json_object *ArrayKeyData = NULL;
    json_object *TLVsData = NULL;
    json_object *TLVData = NULL;
    json_object *subtype = NULL;
    json_object *subtypeVal = NULL;
    json_object *TLVSentry = NULL;
    json_object *TLVentry = NULL;
    json_object *ValueLen = NULL;

    bundle_key *Pbundlekey = NULL;

    bundle_key *Pbundlekeydata = NULL;

    int ArrayData1Len = 0;
    int TLVDataLen = 0;
    int k = 0, j = 0, q =0;
    int cnt = 0;

    unsigned char OriValue[MAX_VERSION_TEXT_LENGTH + 1]={0};
    int OriValueLen = 0;


    remove(SZ_LLDP_SHOW_OBD_OUTFNAME);
    doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_OBD_OUTFNAME);

    NeighborListObj = json_object_from_file(SZ_LLDP_SHOW_OBD_OUTFNAME);

    DBG_INFO("%s:%d Output neighbor to %s\n", __FUNCTION__, __LINE__, SZ_LLDP_SHOW_OBD_OUTFNAME);
    if (NeighborListObj)
    {
        json_object_object_get_ex(NeighborListObj, "lldp", &InterfaceData);
        if (InterfaceData)
        {
            json_object_object_get_ex(InterfaceData, "interface", &ArrayData1);
            if (ArrayData1)
            {
                if (json_object_get_type(ArrayData1) == json_type_array)
                {
                    ArrayData1Len = json_object_array_length(ArrayData1);

                    Pbundlekey = (struct _bundle_key *) malloc(ArrayData1Len *sizeof(struct _bundle_key));

                    memset(Pbundlekey, 0x00, ArrayData1Len *sizeof(struct _bundle_key));

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    for (k = 0; k < ArrayData1Len; k++)
                    {
                        TLVSentry = json_object_array_get_idx(ArrayData1, k);

                        json_object_object_foreach(TLVSentry, key, ArrayKeyData)
                        {
                            DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                            if(ArrayKeyData)
                            {
                                json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                                if (TLVsData)
                                {
                                    json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                    if (json_object_get_type(TLVData) != json_type_array)
                                        goto amas_get_bundle_key_Fail;

                                    TLVDataLen = json_object_array_length(TLVData);
                                    DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);
                                    for (j = 0; j < TLVDataLen; j++)
                                    {
                                        TLVentry = json_object_array_get_idx(TLVData, j);
                                        json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                        json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                        if (ValueLen) {
                                            OriValueLen = json_object_get_int(ValueLen);
                                            DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                            //OriValue = malloc(OriValueLen * sizeof(char));
                                            memset(OriValue, 0x00, sizeof(OriValue));
                                        }
                                        if (subtype)
                                        {
                                            DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                            if(json_object_get_int(subtype) == AMAS_SUBTYPE_HASH_BUNDLE_KEY) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                if(subtypeVal) {
                                                    STR2HEX(Pbundlekey[k].bundlekey, json_object_get_string(subtypeVal), OriValueLen);
                                                    Pbundlekey[k].bundlekeylen = OriValueLen;
                                                }
                                            }
                                            else if(json_object_get_int(subtype) == AMAS_SUBTYPE_COST) {
                                                json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                                DBG_INFO("%s:%d subtypeVal = %s\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal));
                                                if(subtypeVal) {
                                                    STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                    HEXVAL(OriValue, Pbundlekey[k].cost, OriValueLen);
                                                }
                                            }
                                        }
                                        else
                                            goto amas_get_bundle_key_Fail;

                                    }
                                    DBG_INFO("%s:%d  Entry[%d] bundle key len =%d", __FUNCTION__,__LINE__,k, Pbundlekey[k].bundlekeylen);
                                    DBG_INFO("%s:%d  Entry[%d] bundle key =", __FUNCTION__,__LINE__, k);
                                    for(q = 0; q < Pbundlekey[k].bundlekeylen; q++)
                                        DBG_INFO("%02X ", Pbundlekey[k].bundlekey[q]);
                                    DBG_INFO("Pbundlekey[%d].cost(%d)", k,  Pbundlekey[k].cost);
                                    DBG_INFO("\n");

                                }
                            }
                        }

                    }
                }
                else {
                    ArrayData1Len = 1;

                    Pbundlekey = (struct _bundle_key *) malloc(ArrayData1Len *sizeof(struct _bundle_key));
                    memset(Pbundlekey, 0x00, ArrayData1Len *sizeof(struct _bundle_key));

                    DBG_INFO("%s:%d ArrayData1Len = %d\n", __FUNCTION__, __LINE__, ArrayData1Len);

                    json_object_object_foreach(ArrayData1, key, ArrayKeyData)
                    {
                        DBG_INFO("%s:%d interface = %s\n", __FUNCTION__, __LINE__, key);

                        if(ArrayKeyData)
                        {
                            json_object_object_get_ex(ArrayKeyData, "unknown-tlvs\0", &TLVsData);

                            if (TLVsData)
                            {
                                json_object_object_get_ex(TLVsData, "unknown-tlv\0", &TLVData);

                                if (json_object_get_type(TLVData) != json_type_array)
                                    goto amas_get_bundle_key_Fail;

                                TLVDataLen = json_object_array_length(TLVData);
                                DBG_INFO("%s:%d TLVDataLen = %d\n", __FUNCTION__, __LINE__, TLVDataLen);
                                for (j = 0; j < TLVDataLen; j++)
                                {
                                    TLVentry = json_object_array_get_idx(TLVData, j);
                                    json_object_object_get_ex(TLVentry, "subtype", &subtype);

                                    json_object_object_get_ex(TLVentry, "len", &ValueLen);
                                    if (ValueLen) {
                                        OriValueLen = json_object_get_int(ValueLen);
                                        DBG_INFO("%s:%d OriValueLen = %d\n", __FUNCTION__, __LINE__, OriValueLen);
                                        //OriValue = malloc(OriValueLen * sizeof(char));
                                        memset(OriValue, 0x00, sizeof(OriValue));
                                    }
                                    if (subtype) {
                                        DBG_INFO("%s:%d subtype = %d\n", __FUNCTION__, __LINE__, json_object_get_int(subtype));
                                        if(json_object_get_int(subtype) == AMAS_SUBTYPE_HASH_BUNDLE_KEY) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            if(subtypeVal) {
                                                DBG_INFO("%s:%d json_object_get_string(subtypeVal) = %s\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal));
                                                STR2HEX(Pbundlekey[k].bundlekey, json_object_get_string(subtypeVal), OriValueLen);
                                                Pbundlekey[k].bundlekeylen = OriValueLen;
                                            }
                                        }
                                        else if(json_object_get_int(subtype) == AMAS_SUBTYPE_COST) {
                                            json_object_object_get_ex(TLVentry, "value", &subtypeVal);
                                            DBG_INFO("%s:%d subtypeVal = %s\n", __FUNCTION__, __LINE__, json_object_get_string(subtypeVal));
                                            if(subtypeVal) {
                                                STR2HEX(OriValue, json_object_get_string(subtypeVal), OriValueLen);
                                                HEXVAL(OriValue, Pbundlekey[k].cost, OriValueLen);
                                            }
                                        }
                                    }
                                    else
                                        goto amas_get_bundle_key_Fail;
                                }
                                DBG_INFO("############################################################\n");
                                DBG_INFO("%s:%d  Entry[%d] bundle key len =%d", __FUNCTION__,__LINE__,k, Pbundlekey[k].bundlekeylen);
                                DBG_INFO("%s:%d  Entry[%d] bundle key =", __FUNCTION__,__LINE__, k);
                                for(q = 0; q < Pbundlekey[k].bundlekeylen; q++)
                                    DBG_INFO("%02X ", Pbundlekey[k].bundlekey[q]);
                                DBG_INFO("Pbundlekey[%d].cost(%d)", k,  Pbundlekey[k].cost);
                                DBG_INFO("\n");
                                DBG_INFO("############################################################\n");
                            }
                        }
                    }
                }
            }
        }

    }
    if (ArrayData1Len > 0) {
        Pbundlekeydata = (struct _bundle_key *) malloc(ArrayData1Len *sizeof(struct _bundle_key));
        memset(Pbundlekeydata, 0x00, ArrayData1Len *sizeof(struct _bundle_key));
        cnt = remove_unnecessary_bundle_key(Pbundlekey, Pbundlekeydata, ArrayData1Len);

        DBG_INFO("Entry count = %u\n", cnt);

        if(cnt > 0) {
            *P_bundlekey = (struct _bundle_key *) Pbundlekeydata;
        }
        else if (cnt == 0) {
            free(Pbundlekeydata);
        }
    }


    if (!IsNULL_PTR(len)) *(len) = cnt;

    if (NeighborListObj)
        json_object_put(NeighborListObj);


    if (Pbundlekey)
        free(Pbundlekey);

    RETURN_AMAS_RESULT_SUCCESS;

amas_get_bundle_key_Fail:
    if (NeighborListObj)
        json_object_put(NeighborListObj);

    if (Pbundlekey)
        free(Pbundlekey);

    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_get_default_hash_bundle_key(unsigned char *hash_key, int hash_key_len)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    unsigned char *key = NULL;
    unsigned char *bundle_key = NULL, bundle_key_hex[16];
    size_t keyLen = 0;

    bundle_key = nvram_safe_get("amas_bdlkey");
    if (IsNULL_PTR(bundle_key) || strlen(bundle_key) <= 0)
    {
        DBG_ERR("bundle key is invalid\n");
        SET_ERROR_CODE(AMAS_RESULT_GET_DEF_HASH_BUNDLE_KEY_FAILED);
        goto amas_get_default_hash_bundle_key_Fail;
    }

    memset(bundle_key_hex, 0, sizeof(bundle_key_hex));
    str2hex_x(bundle_key, bundle_key_hex);
    key = gen_sha256_key(bundle_key_hex, sizeof(bundle_key_hex), &keyLen);
    DBG_INFO("keyLen (%d), hash_key_len (%d)\n", keyLen, hash_key_len);
    if (IsNULL_PTR(key) || keyLen <= 0 || keyLen != hash_key_len)
    {
        DBG_ERR("key is invalid\n");
        SET_ERROR_CODE(AMAS_RESULT_GET_DEF_HASH_BUNDLE_KEY_FAILED);
        goto amas_get_default_hash_bundle_key_Fail;
    }

    memcpy(hash_key, key, keyLen);

    if (key) free(key);

    RETURN_AMAS_RESULT_SUCCESS;

amas_get_default_hash_bundle_key_Fail:
    RETURN_AMAS_RESULT_FAILED;
}
//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_prelink_band_sync_bypass(int unit, int *result)
{
    int prelink = nvram_invmatch("amas_bdlkey", "");
    char prefix[]="wlXXXXXXX_", prelink_ssid[100], prelink_psk[100], tmp[100];
    int res = 0;
    int wlif_count = num_of_wl_if();

    *result = 0;

    if (prelink && wlif_count == (unit + 1)) {
        snprintf(prefix, sizeof(prefix), "wl%d_", unit);
        strlcpy(prelink_ssid, nvram_safe_get(strcat_r(prefix, "ssid", tmp)), sizeof(prelink_ssid));
        strlcpy(prelink_psk, nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp)), sizeof(prelink_psk));
        DBG_INFO("unit (%d), prelink ssid (%s), prelink psk (%s)\n", unit, prelink_ssid, prelink_psk);
        if (amas_verify_default_backhaul_security(prelink_ssid, prelink_psk, &res) == AMAS_RESULT_SUCCESS)
        {
            if (res == 1) {
               DBG_INFO("meet prelink default backhaul security\n");
               *result = 1;
            }
            else
               DBG_INFO("doesn't meet prelink default backhaul security\n");
        }
    }

    RETURN_AMAS_RESULT_SUCCESS;
}
#endif  /* RTCONFIG_PRELINK */

#ifdef RTCONFIG_VIF_ONBOARDING
AMAS_FUNC AMAS_RESULT
AMAS_API amas_gen_onboarding_vif_security(char *ssid, int ssid_len, char *psk, int psk_len)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;

    if (gen_onboarding_vif_security(ssid, ssid_len, psk, psk_len) == 0) {
        SET_ERROR_CODE(AMAS_RESULT_GEN_ONBOARDING_VIF_WIFI_SECURITY_FAILED);
        goto amas_gen_onboarding_vif_security_Fail;
    }

    RETURN_AMAS_RESULT_SUCCESS;

amas_gen_onboarding_vif_security_Fail:
    RETURN_AMAS_RESULT_FAILED;
}
#endif  /* RTCONFIG_VIF_ONBOARDING */

//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_set_misc_info(int index, char *value)
{
    json_object *MiscInfoObj;
    char index_str[8];

    if (index <= 0) {
        DBG_ERR("index is invalid\n");
        SET_ERROR_CODE(AMAS_RESULT_SET_MISC_INFO_FAILED);
        goto amas_set_misc_info_Fail;
    }

    if (IsNULL_PTR(value) || strlen(value) == 0) {
        DBG_ERR("value is invalid\n");
        SET_ERROR_CODE(AMAS_RESULT_SET_MISC_INFO_FAILED);
        goto amas_set_misc_info_Fail;
    }

    snprintf(index_str, sizeof(index_str), "%d", index);

    if (check_if_file_exist(MISC_INFO_FILE_PATH)) {
        MiscInfoObj = json_object_from_file(MISC_INFO_FILE_PATH);

        if (MiscInfoObj)
           json_object_object_del(MiscInfoObj, index_str);
        else
            MiscInfoObj = json_object_new_object();
    }
    else
    {
        MiscInfoObj = json_object_new_object();
    }

    if (MiscInfoObj) {
        json_object_object_add(MiscInfoObj, index_str, json_object_new_string(value));
        json_object_to_file(MISC_INFO_FILE_PATH, MiscInfoObj);
    }

    json_object_put(MiscInfoObj);
    RETURN_AMAS_RESULT_SUCCESS;

amas_set_misc_info_Fail:
    RETURN_AMAS_RESULT_FAILED;
}


//---------------------------------------------------------------------------
AMAS_FUNC AMAS_RESULT
AMAS_API amas_get_misc_info(unsigned char *misc_info, int *misc_info_len)
{
    json_object *MiscInfoObj;
    unsigned char c, *data;
    int len, index, offset = 0;

    *misc_info_len = 0;

    if (!check_if_file_exist(MISC_INFO_FILE_PATH)) {
        DBG_INFO("%s doesn't exist\n", MISC_INFO_FILE_PATH);
        RETURN_AMAS_RESULT_SUCCESS;
    }

    if (IsNULL_PTR(misc_info)) {
        DBG_ERR("misc_info is invalid\n");
        SET_ERROR_CODE(AMAS_RESULT_GET_MISC_INFO_FAILED);
        goto amas_get_misc_info_Fail;
    }

    MiscInfoObj = json_object_from_file(MISC_INFO_FILE_PATH);

    if (MiscInfoObj) {
        json_object_object_foreach(MiscInfoObj, MiscInfokey, MiscInfoData) {
            index = atoi(MiscInfokey);
            data = (unsigned char *)json_object_get_string(MiscInfoData);
            len = strlen(data);

            c = index;
            memcpy(misc_info + offset, &c, 1);
            c = len;
            offset += 1;
            memcpy(misc_info + offset, &c, 1);
            offset += 1;
            memcpy(misc_info + offset, data, len);
            offset += len;
        }
    }

    *misc_info_len = offset;
    json_object_put(MiscInfoObj);

    RETURN_AMAS_RESULT_SUCCESS;

amas_get_misc_info_Fail:
    RETURN_AMAS_RESULT_FAILED;
}

#ifdef RTCONFIG_QCA_PLC2
AMAS_FUNC AMAS_RESULT
AMAS_API amas_is_plc_head(
    char *ifname,
    int *is_plc_head)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;

    if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_cost_mac_Fail;
    }

    if (IsNULL_PTR(is_plc_head))
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_get_cost_mac_Fail;
    }

#if defined(USE_LLDP_CTRL)
    v = lldp_is_plc_head(ifname, &res);
#else
#error NEED to implement
#endif	/* USE_LLDP_CTRL */
    if (res != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_get_cost_mac_Fail;
    }
    if (!IsNULL_PTR(is_plc_head)) *(is_plc_head) = v;
    RETURN_AMAS_RESULT_SUCCESS;

amas_get_cost_mac_Fail:
    if (!IsNULL_PTR(is_plc_head)) *(is_plc_head) = 0;
    RETURN_AMAS_RESULT_FAILED;
}

AMAS_FUNC AMAS_RESULT
AMAS_API amas_find_mac_role(
    char *ifname,
    char *mac,
    int *role)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;

    if (IsNULL_PTR(ifname) || strlen(ifname) <= 0 || IsNULL_PTR(mac) || strlen(mac) != 17 || IsNULL_PTR(role))
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_find_mac_Fail;
    }

#if defined(USE_LLDP_CTRL)
    v = lldp_find_mac_role(ifname, mac, &res);
#else
#error NEED to implement
#endif	/* USE_LLDP_CTRL */
    if (res != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_find_mac_Fail;
    }
    if (!IsNULL_PTR(role)) (*role) = v;
    RETURN_AMAS_RESULT_SUCCESS;

amas_find_mac_Fail:
    if (!IsNULL_PTR(role)) (*role) = -1;
    RETURN_AMAS_RESULT_FAILED;
}

AMAS_FUNC AMAS_RESULT
AMAS_API amas_find_role_lan(
    char *ifname,
    char *mac)
{
    AMAS_RESULT res = AMAS_RESULT_FAILED;
    int v = 0;

    if (IsNULL_PTR(ifname) || strlen(ifname) <= 0 || IsNULL_PTR(mac))
    {
        SET_ERROR_CODE(AMAS_RESULT_INVALID_VALUE);
        goto amas_find_role_lan_Fail;
    }

#if defined(USE_LLDP_CTRL)
    v = lldp_find_role_lan(ifname, mac, &res);
#else
#error NEED to implement
#endif	/* USE_LLDP_CTRL */
    if (res != AMAS_RESULT_SUCCESS)
    {
        SET_ERROR_CODE(res);
        goto amas_find_role_lan_Fail;
    }
    RETURN_AMAS_RESULT_SUCCESS;

amas_find_role_lan_Fail:
    RETURN_AMAS_RESULT_FAILED;
}
#endif


