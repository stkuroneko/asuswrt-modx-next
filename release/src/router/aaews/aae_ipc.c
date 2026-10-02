#include <stdio.h>
#include <sys/select.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <pthread.h>

#include "aae_ipc.h"

/*
========================================================================
Routine Description:
  Send data to specificed IPC socket path.

Arguments:
  ipcPath   - ipc socket path
  data    - data will be sent out
  dataLen   - the length of data

Return Value:
  0   - fail
  1   - success

========================================================================
*/
int aae_sendIpcMsg(char *ipcPath, char *data, int dataLen)
{
  int fd = -1;
  int length = 0;
  int ret = 0;
  struct sockaddr_un addr;
  int flags;
  int status;
  socklen_t statusLen;
  fd_set writeFds;
  int selectRet;
  struct timeval timeout = {2, 0};
  struct aaeIpcArgStruct ipcArgs;

  printf("aae_sendIpcMsg enter\n");

  printf("enter AF_UNIX = %d\n", AF_UNIX);
  printf("enter SOCK_STREAM = %d\n", SOCK_STREAM);
  
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    printf("ipc socket error!\n");
    goto err;
  }

  /* set NONBLOCK for connect() */
  if ((flags = fcntl(fd, F_GETFL)) < 0) {
    printf("F_GETFL error!");
    goto err;
  }

  printf("flags = %d\n", flags);

  flags |= O_NONBLOCK;

  printf("flags = %d\n", flags);

  if (fcntl(fd, F_SETFL, flags) < 0) {
    printf("F_SETFL error!\n");
    goto err;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, ipcPath, sizeof(addr.sun_path)-1);

  printf("addr.sun_path  = %s\n", addr.sun_path);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {

    if (errno == EINPROGRESS) {
      FD_ZERO(&writeFds);
      FD_SET(fd, &writeFds);

      selectRet = select(fd + 1, NULL, &writeFds, NULL, &timeout);

      //Check return, -1 is error, 0 is timeout
      if (selectRet == -1 || selectRet == 0) {
        printf("ipc connect error : %s\n", strerror(errno));
        goto err;
      }
    }
    else
    {
      printf("ipc connect error : %s\n", strerror(errno));
      goto err;
    }
  }

  /* check the status of connect() */
  status = 0;
  statusLen = sizeof(status);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &statusLen) == -1) {
    // DBG_ERR("getsockopt(SO_ERROR): %s\n", strerror(errno));
    printf("getsockopt(SO_ERROR): %s\n", strerror(errno));
    goto err;
  }

  //length = write(fd, data, dataLen);
  memset(&ipcArgs, 0, sizeof(struct aaeIpcArgStruct));
  memcpy(ipcArgs.data, data, dataLen);
  length = send(fd, &ipcArgs, sizeof(struct aaeIpcArgStruct), MSG_NOSIGNAL);

  if (length < 0) {
    // DBG_ERR("error writing:%s\n", strerror(errno));
    printf("error writing:%s\n", strerror(errno));
    goto err;
  }

  ret = 1;

  // DBG_INFO("send data out (%s) via (%s)\n", data, ipcPath);
  printf("send data out (%s) via (%s)\n", data, ipcPath);

err:
  if (fd >= 0)
    close(fd);

  // DBG_INFO("leave");
  printf("aae_sendIpcMsg leave\n");
  return ret;
} /* End of aae_sendIpcMsg */


/*
========================================================================
Routine Description:
  Send data to specificed IPC socket path.

Arguments:
  ipcPath   - ipc socket path
  data    - data will be sent out
  dataLen   - the length of data

Return Value:
  0   - fail
  1   - success

========================================================================
*/
int aae_sendIpcMsgAndWaitResp(char *ipcPath, char *data, int dataLen, char *out, int outLen, int timeout_sec)
{
  int fd = -1;
  int length = 0;
  int ret = 0;
  struct sockaddr_un addr;
  int flags;
  int status;
  socklen_t statusLen;
  fd_set writeFds, readFds;
  int selectRet;
  int timeout_usec = 0;
  struct timeval timeout = {2, 0};
  struct aaeIpcArgStruct ipcArgs, ipcArgsResp;

  // DBG_INFO("enter");
  printf("aae_sendIpcMsg enter\n");

  printf("enter AF_UNIX = %d\n", AF_UNIX);
  printf("enter SOCK_STREAM = %d\n", SOCK_STREAM);
  
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    // DBG_ERR("ipc socket error!");
    printf("ipc socket error!\n");
    goto err;
  }

  /* set NONBLOCK for connect() */
  if ((flags = fcntl(fd, F_GETFL)) < 0) {
    // DBG_ERR("F_GETFL error!");
    printf("F_GETFL error!");
    goto err;
  }

  printf("flags = %d\n", flags);

  flags |= O_NONBLOCK;

  printf("flags = %d\n", flags);

  if (fcntl(fd, F_SETFL, flags) < 0) {
    // DBG_ERR("F_SETFL error!");
    printf("F_SETFL error!\n");
    goto err;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, ipcPath, sizeof(addr.sun_path)-1);

  printf("addr.sun_path  = %s\n", addr.sun_path);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {

    if (errno == EINPROGRESS) {
      FD_ZERO(&writeFds);
      FD_SET(fd, &writeFds);

      selectRet = select(fd + 1, NULL, &writeFds, NULL, &timeout);

      //Check return, -1 is error, 0 is timeout
      if (selectRet == -1 || selectRet == 0) {
        // DBG_ERR("ipc connect error");
        printf("ipc connect error : %s\n", strerror(errno));
        goto err;
      }
    }
    else
    {
      printf("ipc connect error : %s\n", strerror(errno));
      goto err;
    }
  }

  /* check the status of connect() */
  status = 0;
  statusLen = sizeof(status);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &statusLen) == -1) {
    // DBG_ERR("getsockopt(SO_ERROR): %s\n", strerror(errno));
    printf("getsockopt(SO_ERROR): %s\n", strerror(errno));
    goto err;
  }

  /*if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(struct timeval)) < 0) {
    printf("setsockopt(SO_RCVTIMEO): %s\n", strerror(errno));
    goto err;
  }
  printf("setsockopt(SO_RCVTIMEO) success\n");
  if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(struct timeval)) < 0) {
    printf("setsockopt(SO_SNDTIMEO): %s\n", strerror(errno));
    goto err;
  }
  printf("setsockopt(SO_SNDTIMEO) success\n");*/

  //length = write(fd, data, dataLen);
  memset(&ipcArgs, 0, sizeof(struct aaeIpcArgStruct));
  memcpy(ipcArgs.data, data, dataLen);
  ipcArgs.waitResp = 1;
  length = send(fd, &ipcArgs, sizeof(struct aaeIpcArgStruct), MSG_NOSIGNAL);

  if (length < 0) {
    // DBG_ERR("error writing:%s\n", strerror(errno));
    printf("error writing:%s\n", strerror(errno));
    goto err;
  }
  // DBG_INFO("send data out (%s) via (%s)\n", data, ipcPath);
  printf("send data out (%s) via (%s)\n", data, ipcPath);

  int retry_cnt = 0;
  timeout_usec = timeout_sec * 1000000;
  while (retry_cnt < timeout_usec) {  // retry 5 times
    FD_ZERO(&readFds);
    FD_SET(fd, &readFds);
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    selectRet = select(fd + 1, &readFds, NULL, NULL, &timeout);
    //Check return, -1 is error, 0 is timeout
    if (selectRet == -1)  {
      printf(" ipc read error : %s\n", strerror(errno));
      if (errno == EINTR)
        continue;
      goto err;
    } else if (selectRet == 0) {
      retry_cnt += 100000;
      //printf(" ipc read timeout, retry=%d\n", retry_cnt);
      continue;
    }

    length = read(fd, &ipcArgsResp, sizeof(struct aaeIpcArgStruct));

    if (length < 0) {
      printf(" ipc read error : %s\n", strerror(errno));
      if (errno != EAGAIN)
        goto err;
    } else {
      printf(" ipc read length=%d\n", length);
    }
    break;
  }

  memset(out, 0, outLen);
  memcpy(out, ipcArgsResp.data, outLen > length ? length : (outLen - 1));
  // DBG_INFO("send data out (%s) via (%s)\n", data, ipcPath);
  printf("get data in (%s) via (%s)\n", ipcArgsResp.data, ipcPath);

  ret = 1;


err:
  if (fd >= 0)
    close(fd);

  // DBG_INFO("leave");
  printf("aae_sendIpcMsg leave\n");
  return ret;
} /* End of aae_sendIpcMsg */