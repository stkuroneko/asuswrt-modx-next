/******************************************************************************

                               Copyright (c) 2014
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/*! \def MAX_NAME_LEN 
    \brief Macro that defines number of elements in an array.
 */
#define MAX_NAME_LEN 64

/*! \def IPC_SUCCESS 
    \brief Macro that defines success state.
 */

#define IPC_SUCCESS 0

/*! \def IPC_FAIL
    \brief Macro that defines failure state.
 */

#define IPC_FAIL -1

/*! \def MAX_MODID_LEN 
    \brief Macro that defines Max Module Id Length.
 */

#define MAX_MODID_LEN 32

typedef struct
{
   /* ID of the module sending the message */
   unsigned char aucfrom[MAX_MODID_LEN];
   /* ID of the module to which the message is addressed */
   unsigned char aucto[MAX_MODID_LEN];
   /* ucTo may be just used for strict validation, since
      the message destined for a module will be in the 
      module's FIFO anyway
    */
   /* Size of the Message */
   uint16_t unmsgsize;
   /* Msg type can be passed here for receiver to know how to interpret acMsg */
   int16_t nMsgType;
   /* Reserved for future use */
   uint32_t uireserved;
   /* Shared memory key used for get q/cl  */
   uint32_t shm_key;
   /* Response code used for errors  */
   int32_t respCode;
} x_ipc_msghdr_t;

typedef struct{
        int32_t ifd; /* Socket Id */
        int32_t iconnfd; /*Connection Id */
}x_ipc_handle;


/*! \def IPC_HDR_SIZE 
    \brief Macro that defines IPC Header Size.
 */
#define IPC_HDR_SIZE sizeof(x_ipc_msghdr_t)

/*! \def IPC_MAX_MSG_SIZE
    \brief Macro that defines Max MSG Size .
 */
#define IPC_MAX_MSG_SIZE (4192 - IPC_HDR_SIZE)

typedef struct
{
   x_ipc_msghdr_t xhdr;
   /* Buffer to contain the message */
   char acmsg[IPC_MAX_MSG_SIZE];
   /* Each module is expected to write a union in the acMsg part */
} x_ipc_msg_t;


/*! \brief   ipc_send_request to send connection request to server 
   \params Message to be passed 
*/
int32_t
ipc_send_request(x_ipc_msg_t *pxmsg);

/*! \brief ipc_recv message from client/server 
   \params Socket Id and Message to be passed 
*/
int32_t
ipc_recv(void *pvhandle,
                                 x_ipc_msg_t *pxmsg);

/*! \brief ipc_create_listener Listen to the client request */ 

void*
ipc_create_listener(char *pucto);

/*! \brief ipc_send_reply to client/server 
   \params Socket Id and Message to be passed 
*/
int32_t
ipc_send_reply(void *pvhandle,
               x_ipc_msg_t *pxmsg);

/*! \brief ipc_get_memory allocates a shared memory segment  */
int32_t ipc_get_memory(uint32_t *shm_key, int32_t *shm_id, char **data, uint32_t size, int32_t create);

/*! \brief ipc_delete_memory deattach a shared memory segment  */
int32_t ipc_delete_memory(int32_t shm_id, char **data, int32_t delete);
