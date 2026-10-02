

#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <pthread.h>

#include <json.h>

#include <nat_nvram.h>

#include "ssl_api.h"
#include "nw_util.h"
#include "aae_ipc.h"
#include "aae_ipc_handler.h"

#include "log.h"

#include "common.h"
#include "wb.h"
#include "ws_caller.h"

CM_CTRL aae_ctrlBlock;

static void aae_closeSocket(CM_CTRL *pCtrlBK);
static int aae_openSocket(CM_CTRL *pCtrlBK);

#define IPC_DBG 1
 
pthread_attr_t *attrp;

extern int aae_sendIpcMsg(char *ipcPath, char *data, int dataLen);
extern int aae_login(GetServiceArea *gsa, Login *lg);

#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
extern int g_is_in_awsiot_trigger_mode;
#endif

/*
========================================================================
Routine Description:
  Process packets from awsiot.

Arguments:
  ipcArgs    - received data

Return Value:
  0   - continue to receive
        1   - break to receive

========================================================================
*/
int aae_awsiotPacketProcess(struct aaeIpcArgStruct *ipcArgs)
{
  json_object *root = NULL;
  json_object *awsiotObj = NULL;
  json_object *eidObj = NULL;
  json_object *calleeObj = NULL;
  int eid = 0;
  int ret = 0;
  unsigned char *data;
  int status = -1;
  char resp_status[8] = {0};

  if (!ipcArgs)
    return -1;

  data = &ipcArgs->data[0];
  root = json_tokener_parse((char *)data);
  json_object_object_get_ex(root, AAE_AWSIOT_PREFIX, &awsiotObj);
  json_object_object_get_ex(awsiotObj, AAE_IPC_EVENT_ID, &eidObj);

  Cdbg(IPC_DBG, "received data (%s)", data);

  if (eidObj) {
    eid = json_object_get_int(eidObj);
    if (eid == EID_AWSIOT_TUNNEL_ENABLE) {
      if ((!pids("aaews"))) {
        char cmd[64];
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
        g_is_in_awsiot_trigger_mode = 1; // for checking aaews is ready.
#endif
        nvram_set_int("aae_disable_fast_init", 1);
        sprintf( cmd , "aaews --sdk_log_dir=/tmp &");
        int sys_code = system( cmd );

        Cdbg(IPC_DBG, "aaews start run -> sys_code = %d", sys_code);
      } else {
        Cdbg(IPC_DBG, "aaews running");
        if(nvram_match("aae_sip_connected", "1")) {
          char status_str[256];
          snprintf(status_str, sizeof(status_str), AAE_TUNNEL_STATUS_RES, 1);
          aae_sendIpcMsg(AWSIOT_IPC_SOCKET_PATH, status_str, strlen(status_str));
        } else {
          start_sip_conn();
        }
      }
    } else if (eid == EID_AWSIOT_TUNNEL_TEST) {
#define S2S_AAEUAC_TNL_TEST_PATH "/tmp/s2s_aaeuac_tnl_test"
      char result[256] = {0};
	    pid_t pid;
      json_object_object_get_ex(awsiotObj, "callee_id", &calleeObj);
      if (calleeObj) {
        char *callee_id = json_object_get_string(calleeObj);
		    int check_count = 30;
        unlink(S2S_AAEUAC_TNL_TEST_PATH);

	      char *argv[] = {"aaeuac", "AWSIOT", callee_id, S2S_AAEUAC_TNL_TEST_PATH, NULL};
        _eval(argv, NULL, 0, &pid);

        while(check_count>0){
          if(f_read_string(S2S_AAEUAC_TNL_TEST_PATH, result, sizeof(result)) > 0){
            json_object *json_res = NULL;
            if((json_res = json_tokener_parse(result)) == NULL){
              snprintf(result, sizeof(result), AAE_TUNNEL_TEST_RES, nvram_safe_get("aae_deviceid"), callee_id, "unknown", 60000006);
            }
            break;
          }
          sleep(3);
          check_count--;
        }
        if (!check_count || !strlen(result))
          snprintf(result, sizeof(result), AAE_TUNNEL_TEST_RES, nvram_safe_get("aae_deviceid"), callee_id, "unknown", 60000006);
      } else {
        Cdbg(IPC_DBG, "aaeuac tunnel test failed. invalid callee_id.");
        snprintf(result, sizeof(result), AAE_TUNNEL_TEST_RES, nvram_safe_get("aae_deviceid"), "unknown", "unknown", 70004);
      }
      aae_sendIpcMsg(AWSIOT_IPC_SOCKET_PATH, result, strlen(result));
    }

    // Check if need to wait reponse
    if (ipcArgs->waitResp) {
      struct aaeIpcArgStruct resp;
      int length;
      memset(&resp, 0, sizeof(struct aaeIpcArgStruct));
      resp.dataLen = snprintf((char *)resp.data, sizeof(resp.data), AAE_AWSIOT_GENERIC_RESP_MSG, eid, resp_status);
      length = send(ipcArgs->sock, &resp, sizeof(struct aaeIpcArgStruct), MSG_NOSIGNAL);

      if (length < 0) {
        // DBG_ERR("error writing:%s\n", strerror(errno));
        Cdbg(IPC_DBG, "error writing:%s", strerror(errno));
        goto err;
      }
      Cdbg(IPC_DBG, "%d bytes wrote", length);
    }
  } else {
    Cdbg(IPC_DBG, "AWSIOT event failed, invalid eid.");
  }

  ret = 1;
err:

  json_object_put(root);

  return ret;
} /* End of aae_ddnsPacketProcess */

/*
========================================================================
Routine Description:
  Process packets from ddns.

Arguments:
  ipcArgs    - received data

Return Value:
  0   - continue to receive
        1   - break to receive

========================================================================
*/
int aae_ddnsPacketProcess(struct aaeIpcArgStruct *ipcArgs)
{
  json_object *root = NULL;
  json_object *ddnsObj = NULL;
  json_object *eidObj = NULL;
  int eid = 0;
  int ret = 0;
  unsigned char *data;
  int status = -1;
  char resp_status[8] = {0};

  if (!ipcArgs)
    return -1;

  data = &ipcArgs->data[0];
  root = json_tokener_parse((char *)data);
  json_object_object_get_ex(root, AAE_DDNS_PREFIX, &ddnsObj);
  json_object_object_get_ex(ddnsObj, AAE_IPC_EVENT_ID, &eidObj);

  Cdbg(IPC_DBG, "received data (%s)", data);

  if (eidObj) {
    eid = json_object_get_int(eidObj);
    if (eid == AAE_EID_DDNS_REFRESH_TOKEN) {
      // TODO refresh token
      GetUserTicketByRefresh ut;
      char* server = nvram_safe_get("aae_area");
      char* cusid = nvram_safe_get("oauth_dm_cusid");
      char* refresh_ticket = nvram_safe_get("oauth_dm_refresh_ticket");
      char* serviceid = ASUS_DEVICE_ACCOUNT_BINDING_SERVICE;
      char* device_type = DEVICE_TYPE; // 	Linux PC

      if(strlen(cusid)>0 && strlen(refresh_ticket)>0) {
        char fwver[128];
        char *model_name = nvram_safe_get(NVRAM_MODEL_NAME);
        snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));

        unsigned char mac_addr[6];
        get_mac(mac_addr);
        
        DECLARE_CLEAR_MEM(char, md5string, 33);
        DECLARE_CLEAR_MEM(char, mac_str, 18);
      #if NVRAM
        if(nvram_get_mac_addr(mac_str)<0) 
          sprintf(mac_str,"%X:%X:%X:%X:%X:%X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
      #else
        sprintf(mac_str,"%X:%X:%X:%X:%X:%X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
      #endif
        get_md5_string(mac_str, md5string);	

        memset(&ut, 0, sizeof(GetUserTicketByRefresh));
        GetUserTicketByRefresh* gut = &ut;

      	status = send_getuserticketbyrefresh_req(
          server, 
          serviceid, 
          cusid, 
          md5string,
          refresh_ticket,
          device_type, 
          fwver, 
          AIHOME_API_LEVEL,
          model_name,
          gut
        );

        Cdbg(IPC_DBG, "send get user ticket by refresh req, server=%s, status=%d, ut->status=%s, time=%s", server, status, gut->status, gut->time);

        if (status==0 && strcmp(gut->status, "0") == 0) {
          nvram_set("oauth_dm_user_ticket", gut->userticket);
          nvram_commit();
        }

        if (status == 0)
          snprintf(resp_status, sizeof(resp_status), "%s", gut->status);
        else 
          snprintf(resp_status, sizeof(resp_status), "%d", status);
      }
    }

    // Check if need to wait reponse
    if (ipcArgs->waitResp) {
      struct aaeIpcArgStruct resp;
      int length;
      memset(&resp, 0, sizeof(struct aaeIpcArgStruct));
      resp.dataLen = snprintf((char *)resp.data, sizeof(resp.data), AAE_DDNS_GENERIC_RESP_MSG, eid, resp_status);
      length = send(ipcArgs->sock, &resp, sizeof(struct aaeIpcArgStruct), MSG_NOSIGNAL);

      if (length < 0) {
        // DBG_ERR("error writing:%s\n", strerror(errno));
        Cdbg(IPC_DBG, "error writing:%s", strerror(errno));
        goto err;
      }
      Cdbg(IPC_DBG, "%d bytes wrote", length);
    }
  }

  ret = 1;
err:

  json_object_put(root);

  return ret;
} /* End of aae_ddnsPacketProcess */

/*
========================================================================
Routine Description:
  Process packets from ddns.

Arguments:
  ipcArgs    - received data

Return Value:
  0   - continue to receive
        1   - break to receive

========================================================================
*/
int aae_ntcPacketProcess(struct aaeIpcArgStruct *ipcArgs)
{
  json_object *root = NULL;
  json_object *ntcObj = NULL;
  json_object *eidObj = NULL;
  int eid = 0;
  int ret = 0;
  unsigned char *data;
  int status = -1;
  char resp_status[8] = {0};

  if (!ipcArgs)
    return -1;

  data = &ipcArgs->data[0];
  root = json_tokener_parse((char *)data);
  json_object_object_get_ex(root, AAE_NTC_PREFIX, &ntcObj);
  json_object_object_get_ex(ntcObj, AAE_IPC_EVENT_ID, &eidObj);

  Cdbg(IPC_DBG, "received data (%s)", data);

  if (eidObj) {
    eid = json_object_get_int(eidObj);
    if (eid == AAE_EID_NTC_REFRESH_DEVICE_TICKET) {
      GetServiceArea gsa;
      Login lg;

      status = aae_login(&gsa, &lg);
      Cdbg(IPC_DBG, "send login req, server=%s, status=%s", gsa.servicearea, lg.status);

      if (status == 0)
        snprintf(resp_status, sizeof(resp_status), "%s", lg.status);
      else 
        snprintf(resp_status, sizeof(resp_status), "%d", status);
    }

    // Check if need to wait reponse
    if (ipcArgs->waitResp) {
      struct aaeIpcArgStruct resp;
      int length;
      memset(&resp, 0, sizeof(struct aaeIpcArgStruct));
      resp.dataLen = snprintf((char *)resp.data, sizeof(resp.data), AAE_NTC_GENERIC_RESP_MSG, eid, resp_status);
      length = send(ipcArgs->sock, &resp, sizeof(struct aaeIpcArgStruct), MSG_NOSIGNAL);

      if (length < 0) {
        // DBG_ERR("error writing:%s\n", strerror(errno));
        Cdbg(IPC_DBG, "error writing:%s", strerror(errno));
        goto err;
      }
      Cdbg(IPC_DBG, "%d bytes wrote", length);
    }
  }

  ret = 1;
err:

  json_object_put(root);

  return ret;
} /* End of aae_ntcPacketProcess */

/*
========================================================================
Routine Description:
  Process packets from ddns.

Arguments:
  ipcArgs    - received data

Return Value:
  0   - continue to receive
        1   - break to receive

========================================================================
*/
int aae_httpdPacketProcess(struct aaeIpcArgStruct *ipcArgs)
{
  json_object *root = NULL;
  json_object *httpdObj = NULL;
  json_object *eidObj = NULL;
  int eid = 0;
  int ret = 0;
  unsigned char *data;
  int status = -1;
  char resp_status[8] = {0};

  if (!ipcArgs)
    return -1;

  data = &ipcArgs->data[0];
  root = json_tokener_parse((char *)data);
  json_object_object_get_ex(root, AAE_HTTPD_PREFIX, &httpdObj);
  json_object_object_get_ex(httpdObj, AAE_IPC_EVENT_ID, &eidObj);

  Cdbg(IPC_DBG, "received data (%s)", data);

  if (eidObj) {
    eid = json_object_get_int(eidObj);
    if (eid == AAE_EID_HTTPD_PAYLOAD2) {
      json_object *payload2Obj;

      if (json_object_object_get_ex(httpdObj, AAE_HTTPD_PAYLOAD2_PREFIX, &payload2Obj)) {
        RemoteLogin rl;
        char* server = nvram_safe_get("aae_area");
        //char* cusid = nvram_safe_get("oauth_dm_cusid");
        char* serviceid = ASUS_DEVICE_SERVICE;
        char* device_type = DEVICE_TYPE; //   Linux PC
        json_object* joauth_dm_cusid;
        json_object* jmobile_deviceid;
        json_object* jdm_ticket;

        char fwver[128];
        char *model_name = nvram_safe_get(NVRAM_MODEL_NAME);
        snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));

        json_object_object_get_ex(payload2Obj, "oauth_dm_cusid", &joauth_dm_cusid);
        json_object_object_get_ex(payload2Obj, "mobile_deviceid", &jmobile_deviceid);
        json_object_object_get_ex(payload2Obj, "dm_ticket", &jdm_ticket);

        status = send_remotelogin_req(
          server, 
          serviceid, 
          joauth_dm_cusid ? json_object_get_string(joauth_dm_cusid) : "", 
          jmobile_deviceid ? json_object_get_string(jmobile_deviceid) : "", 
          jdm_ticket ? json_object_get_string(jdm_ticket) : "", 
          device_type, 
          fwver, 
          AIHOME_API_LEVEL,
          model_name,
          &rl
        );
        Cdbg(IPC_DBG, "send_remotelogin_req, server=%s", server);

        if (status == 0)
          snprintf(resp_status, sizeof(resp_status), "%s", rl.status);
        else 
          snprintf(resp_status, sizeof(resp_status), "%d", status);
      }
    }

    // Check if need to wait reponse
    if (ipcArgs->waitResp) {
      struct aaeIpcArgStruct resp;
      int length;
      memset(&resp, 0, sizeof(struct aaeIpcArgStruct));
      resp.dataLen = snprintf((char *)resp.data, sizeof(resp.data), AAE_HTTPD_PAYLOAD2_RESP_MSG, eid, resp_status);
      length = send(ipcArgs->sock, &resp, sizeof(struct aaeIpcArgStruct), MSG_NOSIGNAL);

      if (length < 0) {
        // DBG_ERR("error writing:%s\n", strerror(errno));
        Cdbg(IPC_DBG, "error writing:%s", strerror(errno));
        goto err;
      }
      Cdbg(IPC_DBG, "%d bytes wrote", length);
    }
  }

  ret = 1;
err:

  json_object_put(root);

  return ret;
} /* End of aae_ntcPacketProcess */

/*
========================================================================
Routine Description:
  Create a thread to handle received packets from ipc socket.

Arguments:
  *args   - arguments for socket

Return Value:
  None

Note:
========================================================================
*/

void aae_ipcPacketHandler(void *args)
{

    pthread_detach(pthread_self());

    json_object *root = NULL;
    json_object *awsiotObj = NULL;
    json_object *ddnsObj = NULL;
    json_object *ntcObj = NULL;
    json_object *httpdObj = NULL;

    struct aaeIpcArgStruct *ipcArgs = (struct aaeIpcArgStruct *)args;
    unsigned char *pPktBuf = NULL;

    if (ipcArgs->data == NULL) {
        Cdbg(IPC_DBG, "data is null!!");
        goto err;
    }

    pPktBuf = &ipcArgs->data[0];

    Cdbg(IPC_DBG, "aae_ipcPacketHandler msg(%s)", (char *)pPktBuf);

    root = json_tokener_parse((char *)pPktBuf);

    if (root) {
      json_object_object_get_ex(root, AAE_AWSIOT_PREFIX, &awsiotObj);
      json_object_object_get_ex(root, AAE_DDNS_PREFIX, &ddnsObj);
      json_object_object_get_ex(root, AAE_NTC_PREFIX, &ntcObj);
      json_object_object_get_ex(root, AAE_HTTPD_PREFIX, &httpdObj);

      if (awsiotObj)
        aae_awsiotPacketProcess(ipcArgs);

      if (ddnsObj)
        aae_ddnsPacketProcess(ipcArgs);

      if (ntcObj)
        aae_ntcPacketProcess(ipcArgs);

      if (httpdObj)
        aae_httpdPacketProcess(ipcArgs);

      json_object_put(root);

    } else {
      Cdbg(IPC_DBG, "root is invalid");
    }

err:
  if (ipcArgs->sock >= 0) {
    close(ipcArgs->sock);
    Cdbg(IPC_DBG, "close sock");
  }
  free(ipcArgs);
} /* End of aae_ipcPacketHandler */



/*
========================================================================
Routine Description:
  Handle received packets from IPC socket.

Arguments:
  sock    - sock fd for IPC

Return Value:
  None

Note:
========================================================================
*/
void aae_rcvIpcHandler(int sock)
{
  int clientSock = -1;
  pthread_t sockThread;
  struct aaeIpcArgStruct *args = NULL;
  int len = 0;

  Cdbg(IPC_DBG, "enter");

  clientSock = accept(sock, NULL, NULL);

  if (clientSock < 0) {
    Cdbg(IPC_DBG, "aae_rcvIpcHandler Failed to socket accept() !!! (%s)", strerror(errno));
    return;
  }

  args = malloc(sizeof(struct aaeIpcArgStruct));
  memset(args, 0, sizeof(struct aaeIpcArgStruct));

  /* handle the packet */
  if ((len = read(clientSock, args, sizeof(struct aaeIpcArgStruct))) <= 0) {
    Cdbg(IPC_DBG, "aae_rcvIpcHandler Failed to socket read()!!! (%s)", strerror(errno));
    close(clientSock);
    return;
  }

  if (!args->waitResp)
    close(clientSock);
  else {
    args->sock = clientSock;
  }
  Cdbg(IPC_DBG, "aae_rcvIpcHandler create thread for handle ipc packet");
  pthread_attr_t attr;
  pthread_attr_init(&attr);
#ifdef PTHREAD_STACK_SIZE
  pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
  if (pthread_create(&sockThread, &attr, (void *)aae_ipcPacketHandler, args) < 0) {
    Cdbg(IPC_DBG, "could not create thread !!!", strerror(errno));
    free(args);
  }
  pthread_attr_destroy(&attr);

  Cdbg(IPC_DBG, "leave");
} /* End of aae_rcvIpcHandler */


/*
========================================================================
Routine Description:
  Open socket.

Arguments:
  *pCtrlBK  - CM control blcok

Return Value:
  1   - open successfully
  0   - open fail

Note:
========================================================================
*/
static int aae_openSocket(CM_CTRL *pCtrlBK)
{

  struct sockaddr_un sock_addr_ipc;

  /* init */
  pCtrlBK->socketTCPSend = -1;
  pCtrlBK->socketIpcSendRcv = -1;

  Cdbg(IPC_DBG, "AF_UNIX = %d", AF_UNIX);
  Cdbg(IPC_DBG, "SOCK_STREAM = %d", SOCK_STREAM);
  Cdbg(IPC_DBG, "pCtrlBK->socketIpcSendRcv = %d", pCtrlBK->socketIpcSendRcv);
  Cdbg(IPC_DBG, "MASTIFF_IPC_MAX_CONNECTION = %d", MASTIFF_IPC_MAX_CONNECTION);


  /* IPC Socket */
  if ( (pCtrlBK->socketIpcSendRcv = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    Cdbg(IPC_DBG, "Failed to create IPC socket!!! (%s)", strerror(errno));
    goto err;
  }

  memset(&sock_addr_ipc, 0, sizeof(sock_addr_ipc));
  sock_addr_ipc.sun_family = AF_UNIX;

  snprintf(sock_addr_ipc.sun_path, sizeof(sock_addr_ipc.sun_path), "%s", MASTIFF_IPC_SOCKET_PATH);
  unlink(MASTIFF_IPC_SOCKET_PATH);


  if (bind(pCtrlBK->socketIpcSendRcv, (struct sockaddr*)&sock_addr_ipc, sizeof(sock_addr_ipc)) < -1) {
    Cdbg(IPC_DBG, "Failed to bind IPC socket !!! (%s)", strerror(errno));
    goto err;
  }

  if (listen(pCtrlBK->socketIpcSendRcv, MASTIFF_IPC_MAX_CONNECTION) == -1) {
    Cdbg(IPC_DBG, "Failed to listen IPC socket !!! (%s)", strerror(errno));
    goto err;
  }

  return 1;

err:
  aae_closeSocket(pCtrlBK);
  return 0;
} /* End of aae_openSocket */




void *aae_rcvPacket(void *args)
{
  CM_CTRL *pCtrlBK = &aae_ctrlBlock;

  /* init */
  memset(pCtrlBK, 0, sizeof(CM_CTRL));

  pthread_detach(pthread_self());

  Cdbg(IPC_DBG, "aae_rcvPacket enter");

  /* init role */
  // pCtrlBK->role = IS_CLIENT;
  pCtrlBK->role = IS_SERVER;
  pCtrlBK->cost = -1;


  /* get interface info */
  // if (!aae_getIfInfo(pCtrlBK)) {
  //   printf("interface information failed");
    
  // }

  /* init socket */
  if (aae_openSocket(pCtrlBK) == 0) {
    Cdbg(IPC_DBG, "aae_openSocket err");
  }


  /* init */
  pCtrlBK->flagIsTerminated = 0;

  /* waiting for CM packets */
  while(!pCtrlBK->flagIsTerminated)
  {
    aae_rcvHandler(pCtrlBK);
  } 

  Cdbg(IPC_DBG, "aae_rcvPacket leave");

  pthread_exit(NULL);
} /* End of aae_rcvPacket */



/*
========================================================================
Routine Description:
  Handle received CM packets.

Arguments:
  *pCtrlBK  - CM control blcok

Return Value:
  None

Note:
========================================================================
*/
void aae_rcvHandler(CM_CTRL *pCtrlBK)
{
  fd_set fdSet;
  int sockMax;

  /* sanity check */
  if (pCtrlBK->flagIsRunning)
    return;

  /* init */
  pCtrlBK->flagIsRunning = 1;

  Cdbg(IPC_DBG, "pCtrlBK->socketTCPSend(%d)", pCtrlBK->socketTCPSend);

  sockMax = pCtrlBK->socketTCPSend;

  Cdbg(IPC_DBG, "sockMax(%d)", sockMax);
  Cdbg(IPC_DBG, "pCtrlBK->socketIpcSendRcv(%d)", pCtrlBK->socketIpcSendRcv);

  if (pCtrlBK->socketIpcSendRcv > sockMax)
    sockMax = pCtrlBK->socketIpcSendRcv;

  sleep(1);

  /* waiting for any packet */
  while(1)
  {
    /* must re- FD_SET before each select() */
    FD_ZERO(&fdSet);

    FD_SET(pCtrlBK->socketIpcSendRcv, &fdSet);

    /* must use sockMax+1, not sockMax */
    if (select(sockMax+1, &fdSet, NULL, NULL, NULL) < 0)
      break;


    /* handle packets from IPC */
    if (FD_ISSET(pCtrlBK->socketIpcSendRcv, &fdSet)) {
      aae_rcvIpcHandler(pCtrlBK->socketIpcSendRcv);
    }
  };

  pCtrlBK->flagIsRunning = 0;
} /* End of aae_rcvHandler */




static void aae_closeSocket(CM_CTRL *pCtrlBK)
{

  // if (pCtrlBK->socketTCPSend >= 0)
  //   close(pCtrlBK->socketTCPSend);

  // if (pCtrlBK->socketUdpSendRcv >= 0)
  //   close(pCtrlBK->socketUdpSendRcv);

  if (pCtrlBK->socketIpcSendRcv >= 0)
    close(pCtrlBK->socketIpcSendRcv);

} /* End of aae_closeSocket */



void ipc_start()
{
  pthread_t sockThread;

  Cdbg(IPC_DBG, "startThread");

  /* start thread to receive packet */
  pthread_attr_t attr;
  pthread_attr_init(&attr);
#ifdef PTHREAD_STACK_SIZE
  pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
  if (pthread_create(&sockThread, &attr, aae_rcvPacket, NULL) < 0) {
    Cdbg(IPC_DBG, "could not create thread for sockThread (%s)", strerror(errno));
  }
  pthread_attr_destroy(&attr);

}
