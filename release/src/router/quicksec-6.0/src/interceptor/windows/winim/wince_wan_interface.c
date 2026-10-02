/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for handling SSH WAN Interface specific tasks (parses status
   indications and decapsulates/encapsulates WAN packets).
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#ifdef _WIN32_WCE

#include "sshincludes.h"
#include "interceptor_i.h"
#include "wince_wan_interface.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshInterceptorWANInterface"


/* PPP flags */
#define SSH_PPP_FLAG_ACFC    1 /* address and control field compression */
#define SSH_PPP_FLAG_PFC     2 /* protocol field compression */

/* PPP protocol numbers */
#define SSH_PPP_PROTOCOL_IP4        0x0021
#define SSH_PPP_PROTOCOL_IP6        0x0057
#define SSH_PPP_PROTOCOL_IPCP4      0x8021
#define SSH_PPP_PROTOCOL_IPCP6      0x8057
#define SSH_PPP_PROTOCOL_CCP        0x80fd
#define SSH_PPP_PROTOCOL_ECP        0x8053
#define SSH_PPP_PROTOCOL_LCP        0xc021

/* PPP configuration protocol codes */
#define SSH_PPP_CODE_CONFIGURE_REQUEST  1
#define SSH_PPP_CODE_CONFIGURE_REJECT   4
#define SSH_PPP_CODE_PROTOCOL_REJECT    8

/* PPP configuration option types */
#define SSH_PPP_OPTION_IP_COMPRESSION_PROTOCOL   2


typedef struct SshWanReceiveBufferHeaderRec
{
  SshInterceptor interceptor;
  SshNetDataBuffer buffer;
  unsigned char data[1];  /* Actual data buffer follows */  
} SshWanReceiveBufferHeaderStruct, *SshWanReceiveBufferHeader;

typedef struct SshWanSendBufferHeaderRec
{
  SshInterceptor interceptor;
  SshNetDataBuffer buffer;
  NDIS_WAN_PACKET wan_pkt;
  unsigned char data[1];  /* Actual data buffer follows */  
} SshWanSendBufferHeaderStruct, *SshWanSendBufferHeader;

/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

static void
ssh_wan_free_buffer(SshInterceptor interceptor,
                    SshNetDataBuffer buffer)
{
  SshCpuContext cpu_ctx;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(buffer != NULL);

  ssh_kernel_critical_section_start(&interceptor->packet_pool_cs);
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
  ssh_net_buffer_free(interceptor, &cpu_ctx->packet_pool, buffer);
  ssh_kernel_critical_section_end(&interceptor->packet_pool_cs);  
}


static Boolean
ssh_wan_alloc_buffer(SshInterceptor interceptor,
                     SshUInt32 length,
                     SshNetDataBuffer *buf_return,
                     unsigned char **buf_addr_return)
{
  SshCpuContext cpu_ctx;
  SshNetDataBuffer buffer;
  unsigned char *buf_addr;
  SshUInt32 buf_size;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(buf_return != NULL);
  SSH_ASSERT(buf_addr_return != NULL);

  ssh_kernel_critical_section_start(&interceptor->packet_pool_cs);
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
  buffer = ssh_net_buffer_alloc(interceptor, &cpu_ctx->packet_pool);
  ssh_kernel_critical_section_end(&interceptor->packet_pool_cs);  

  if (buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of buffer pool!"));
      return FALSE;
    }

  SSH_RESET_BUFFER(buffer, 0);  

  if (buffer->total_size < length)
    {
      ssh_wan_free_buffer(interceptor, buffer);
      SSH_DEBUG(SSH_D_FAIL, 
                ("Could not allocate contiguous buffer (%u bytes "
                 "requested)", length));
      return FALSE;
    }

  NdisAdjustBufferLength(buffer->nb, length);
  buffer->data_len = length;

  if (!ssh_query_data_block(buffer->nb, &buf_addr, &buf_size))
    {
      ssh_wan_free_buffer(interceptor, buffer);
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to query buffer address!"));
      return FALSE;
    }

  *buf_return = buffer;
  *buf_addr_return = buf_addr;

  return TRUE;
}


/*--------------------------------------------------------------------------
  Allocates a buffer for indicating a PPP packet to a WAN protocol. 
  --------------------------------------------------------------------------*/
static unsigned char *
ssh_wan_alloc_buffer_receive(SshNdisIMAdapter adapter, 
                             SshUInt32 length)
{
  SshWanReceiveBufferHeader buf_hdr;
  SshNetDataBuffer buffer;

  /* Allocate a buffer large enough to contain a pointer to the
     allocated buffer and the packet itself. */
  if (!ssh_wan_alloc_buffer(adapter->interceptor, 
                            length + sizeof(*buf_hdr), 
                            &buffer, (unsigned char **)&buf_hdr))
    return NULL;

  /* Store pointer to the allocated buffer to be able to free it later. */
  buf_hdr->interceptor = adapter->interceptor;
  buf_hdr->buffer = buffer;

  return buf_hdr->data;
}


/*--------------------------------------------------------------------------
  Frees buffer returned by ssh_wan_alloc_buffer_receive().
  --------------------------------------------------------------------------*/
static void
ssh_wan_free_buffer_receive(unsigned char *data_buffer)
{
  SshWanReceiveBufferHeader buf_hdr;

  /* Get the pointer to the allocated buffer and free. */
  buf_hdr = 
    CONTAINING_RECORD(data_buffer, SshWanReceiveBufferHeaderStruct, data);

  ssh_wan_free_buffer(buf_hdr->interceptor, buf_hdr->buffer);
}


/*--------------------------------------------------------------------------
  Allocates a buffer for sending a PPP packet to a WAN adapter.
  --------------------------------------------------------------------------*/
static PNDIS_WAN_PACKET
ssh_wan_alloc_buffer_send(SshNdisIMAdapter adapter, 
                          SshUInt32 length)
{
  SshWanSendBufferHeader buf_hdr;
  SshNetDataBuffer buffer;
  SshUInt32 wan_length;
  PNDIS_WAN_PACKET wan_pkt;

  /* Allocate a buffer large enough to contain the following:
     - a pointer to the allocated buffer
     - an NDIS_WAN_PACKET structure
     - header padding required by the WAN adapter
     - the PPP packet (length octets)
     - tail padding required by the WAN adapter */

  wan_length =
    adapter->wan_header_padding +
    length +
    adapter->wan_tail_padding;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Trying to allocate %u (%u+%u+%u) byte send buffer",
             wan_length, adapter->wan_header_padding, length, 
             adapter->wan_tail_padding));

  if (!ssh_wan_alloc_buffer(adapter->interceptor, 
                            wan_length + sizeof(*buf_hdr), 
                            &buffer, (unsigned char **)&buf_hdr))
    return NULL;

  /* Store pointer to the allocated buffer to be able to free it later. */
  buf_hdr->interceptor = adapter->interceptor;
  buf_hdr->buffer = buffer;
  /* Add the NDIS_WAN_PACKET structure. */
  wan_pkt = &buf_hdr->wan_pkt;
  memset(wan_pkt, 0, sizeof(*wan_pkt));
  /* Packet area follows the NDIS_WAN_PACKET structure. Position the
     packet after header padding and set its size to zero. */
  wan_pkt->StartBuffer = buf_hdr->data;
  wan_pkt->EndBuffer = buf_hdr->data + wan_length;
  wan_pkt->CurrentBuffer = wan_pkt->StartBuffer + adapter->wan_header_padding;
  wan_pkt->CurrentLength = 0;

  return wan_pkt;
}


/*--------------------------------------------------------------------------
  Indicates buffer to WAN protocol.
  --------------------------------------------------------------------------*/
static void
ssh_wan_receive_buffer(SshNdisIMAdapter adapter, 
                       PUCHAR buffer, 
                       ULONG length)
{
  NDIS_STATUS status;

  NdisMWanIndicateReceive(&status, adapter->handle, adapter->wan_link_context,
                          buffer, length);

  if (status != NDIS_STATUS_SUCCESS)
    SSH_DEBUG(SSH_D_FAIL, ("WAN packet not accepted by protocol"));

  ssh_wan_free_buffer_receive(buffer);
}


/*--------------------------------------------------------------------------
  Sends buffer to WAN adapter.
  --------------------------------------------------------------------------*/
static void
ssh_wan_send_buffer(SshNdisIMAdapter adapter, 
                    PNDIS_WAN_PACKET wan_pkt)
{
  NDIS_STATUS status;

  WanMiniportSend(&status, adapter->binding_handle,
                  adapter->wan_link_handle, wan_pkt);

  /* Free allocated buffer unless adapter indicates asynchronous completion.*/
  if (status != NDIS_STATUS_PENDING)
    ssh_wan_free_buffer_send(wan_pkt);
}


/*--------------------------------------------------------------------------
  Decodes a PPP header from the given buffer. Returns TRUE if a valid
  header was completely decoded, FALSE otherwise.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_decode_ppp_header(PUCHAR *pos, 
                          ULONG *len,
                          SshUInt32 *protocol, 
                          SshUInt32 *flags)
{
  PUCHAR start = *pos;

  /* Ensure minimal length for non-compressed PPP address, control and
     protocol fields. */
  if (*len < 4)
    return FALSE;

  *flags = 0;

  /* Skip address and control bytes unless they are omitted by
     Address-and-Control-Field-Compression (ACFC). */
  if (**pos == 0xff)
    *pos += 2;
  else
    *flags |= SSH_PPP_FLAG_ACFC;

  /* Get protocol number; odd first byte indicates
     Protocol-Field-Compression (PFC). */
  if ((**pos & 1))
    {
      *protocol = *(*pos)++;
      *flags |= SSH_PPP_FLAG_PFC;
    }
  else
    {
      *protocol = SSH_GET_16BIT(*pos);
      *pos += 2;
    }

  *len -= *pos - start;
  return TRUE;
}


/*--------------------------------------------------------------------------
  Encodes a PPP header into the given buffer. Return TRUE if the
  header was completely encoded, FALSE otherwise.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_encode_ppp_header(PUCHAR *pos, 
                          ULONG *len,
                          SshUInt32 protocol, 
                          SshUInt32 flags)
{
  PUCHAR start = *pos;

  /* Ensure minimal length for non-compressed PPP address, control and
     protocol fields. */
  if (*len < 4)
    return FALSE;

  /* Add address and control bytes unless they are omitted by
     Address-and-Control-Field-Compression (ACFC). */
  if (!(flags & SSH_PPP_FLAG_ACFC))
    {
      *(*pos)++ = 0xff;
      *(*pos)++ = 0x03;
    }

  /* Add protocol number and compress if Protocol-Field-Compression
     (PFC) is on and compression is possible. */
  if (!(flags & SSH_PPP_FLAG_PFC) || protocol > 0xff)
    {
      SSH_PUT_16BIT(*pos, protocol);
      *pos += 2;
    }
  else
    {
      *(*pos)++ = protocol;
    }

  *len -= *pos - start;
  return TRUE;
}


/*--------------------------------------------------------------------------
  Decodes a PPP control protocol header from the given buffer. Returns
  TRUE if a valid header was completely decoded, FALSE otherwise.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_decode_cp_header(PUCHAR *pos, 
                         ULONG *len,
                         SshUInt32 *code, 
                         SshUInt32 *id, 
                         SshUInt32 *datalen)
{
  if (*len < 4)
    return FALSE;

  *code = *(*pos)++;
  *id = *(*pos)++;

  *datalen = SSH_GET_16BIT(*pos) - 4;
  *pos += 2;

  *len -= 4;

  if (*datalen > *len)
    return FALSE;

  return TRUE;
}


/*--------------------------------------------------------------------------
  Encodes a PPP control protocol header into the given buffer. Returns
  TRUE if the header was completely encoded, FALSE otherwise.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_encode_cp_header(PUCHAR *pos, 
                         ULONG *len, 
                         SshUInt32
                         code, SshUInt32 id, 
                         SshUInt32 datalen)
{
  if (*len < 4) return FALSE;

  *(*pos)++ = (UCHAR)code;
  *(*pos)++ = (UCHAR)id;

  SSH_PUT_16BIT(*pos, datalen + 4);
  *pos += 2;

  *len -= 4;

  if (datalen > *len)
    return FALSE;

  return TRUE;
}


/*--------------------------------------------------------------------------
  Sets the length field of a PPP control protocol frame.
  --------------------------------------------------------------------------*/
static void
ssh_wan_set_cp_length(PUCHAR start, 
                      PUCHAR end)
{
  SSH_PUT_16BIT(start + 2, end - start);
}


/*--------------------------------------------------------------------------
  Decodes a PPP configuration option header from the given
  buffer. Returns TRUE if a valid header was completely decoded, FALSE
  otherwise.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_decode_option_header(PUCHAR *pos, 
                             ULONG *len,
                             SshUInt32 *type, 
                             SshUInt32 *datalen)
{
  SshUInt32 optlen;

  if (*len < 2)
    return FALSE;

  *type = *(*pos)++;
  optlen = *(*pos)++;
  *len -= 2;

  if (optlen < 2)
    return FALSE;

  *datalen = optlen - 2;

  if (*datalen > *len)
    return FALSE;

  return TRUE;
}


/*--------------------------------------------------------------------------
  Encodes a PPP configuration option header into the given
  buffer. Returns TRUE if the header was completely encoded, FALSE
  otherwise.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_encode_option_header(PUCHAR *pos, 
                             ULONG *len,
                             SshUInt32 type, 
                             SshUInt32 datalen)
{
  SshUInt32 optlen;

  if (*len < 2)
    return FALSE;

  optlen = datalen + 2;

  *(*pos)++ = (UCHAR)type;
  *(*pos)++ = (UCHAR)optlen;
  *len -= 2;

  if (datalen > *len)
    return FALSE;

  return TRUE;
}


/*--------------------------------------------------------------------------
  Skips a data block in the given buffer. Returns TRUE if successful,
  FALSE if trying to skip past end of buffer.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_decode_skip(PUCHAR *pos, 
                    ULONG *len, 
                    SshUInt32 datalen)
{
  if (*len < datalen)
    return FALSE;

  *pos += datalen;
  *len -= datalen;
  return TRUE;
}


/*--------------------------------------------------------------------------
  Copies a data block into the given buffer. Returns TRUE if there was
  adequate space, FALSE otherwise.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_encode_data(PUCHAR *pos, 
                    ULONG *len, 
                    PUCHAR databuf, 
                    SshUInt32 datalen)
{
  if (*len < datalen)
    return FALSE;

  memcpy(*pos, databuf, datalen);
  *pos += datalen;
  *len -= datalen;
  return TRUE;
}


/*--------------------------------------------------------------------------
  Encodes an LCP protocol reject packet into the given buffer. Returns
  number of bytes encoded.
  --------------------------------------------------------------------------*/
static SshUInt32
ssh_wan_encode_lcp_protocol_reject(PUCHAR buffer, 
                                   ULONG length,
                                   SshUInt32 ppp_flags, 
                                   SshUInt32 lcp_id,
                                   SshUInt32 protocol,
                                   PUCHAR packet, 
                                   ULONG packet_size)
{
  PUCHAR pos = buffer, start;
  ULONG len = length;

  if (!ssh_wan_encode_ppp_header(&pos, &len, SSH_PPP_PROTOCOL_LCP, ppp_flags))
    return 0;

  start = pos;
  if (!ssh_wan_encode_cp_header(&pos, &len,
                                SSH_PPP_CODE_PROTOCOL_REJECT, lcp_id, 0))
    return 0;

  if (len < 2)
    return 0;

  SSH_PUT_16BIT(pos, protocol);
  pos += 2;
  len -= 2;

  if (packet_size > len)
    packet_size = len;

  ssh_wan_encode_data(&pos, &len, packet, packet_size);
  ssh_wan_set_cp_length(start, pos);
  return pos - buffer;
}


/*--------------------------------------------------------------------------
  Rejects a packet received from a WAN adapter by sending an LCP
  protocol reject packet back to the adapter.
  --------------------------------------------------------------------------*/
static void
ssh_wan_reject_protocol_receive(SshNdisIMAdapter adapter, 
                                SshUInt32 protocol,
                                PUCHAR buffer, 
                                ULONG length)
{
  PNDIS_WAN_PACKET wan_pkt;

  /* Allocate a buffer large enough to contain:
     - PPP header (max 4 octets)
     - LCP header (4 octets)
     - rejected protocol (2 octets)
     - original LCP packet (length octets) */
  wan_pkt = ssh_wan_alloc_buffer_send(adapter, 4 + 4 + 2 + length);
  if (wan_pkt == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate buffer for protocol reject"));
      return;
    }

  wan_pkt->CurrentLength = 
    ssh_wan_encode_lcp_protocol_reject(wan_pkt->CurrentBuffer,
                                  wan_pkt->EndBuffer - wan_pkt->CurrentBuffer,
                                  adapter->ppp_send_flags,
                                  adapter->ppp_send_lcp_id++,
                                  protocol,
                                  buffer,
                                  length);

  ssh_wan_send_buffer(adapter, wan_pkt);
}


/*--------------------------------------------------------------------------
  Rejects a packet sent by a WAN protocol by indicating an LCP
  protocol reject packet back to the protocol.
  --------------------------------------------------------------------------*/
static void
ssh_wan_reject_protocol_send(SshNdisIMAdapter adapter, 
                             SshUInt32 protocol,
                             PUCHAR buffer, 
                             ULONG length)
{
  PUCHAR reject_buf;
  ULONG reject_len;

  /* Allocate a buffer large enough to contain:
     - PPP header (max 4 octets)
     - LCP header (4 octets)
     - rejected protocol (2 octets)
     - original packet (length octets) */
  reject_len = 4 + 4 + 2 + length;
  reject_buf = ssh_wan_alloc_buffer_receive(adapter, reject_len);
  if (reject_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate buffer for protocol reject"));
      return;
    }

  reject_len =
    ssh_wan_encode_lcp_protocol_reject(reject_buf, reject_len,
                                       adapter->ppp_receive_flags,
                                       adapter->ppp_receive_lcp_id++,
                                       protocol,
                                       buffer,
                                       length);

  ssh_wan_receive_buffer(adapter, reject_buf, reject_len);
  NdisMWanIndicateReceiveComplete(adapter->handle,adapter->wan_link_context);
}


/*--------------------------------------------------------------------------
  Decodes an IPCP packet at dpos/dlen, simultaneously building a
  reject packet into epos/elen. Returns TRUE if the reject packet was
  completed and should be sent, FALSE otherwise.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_ipcp_reject(PUCHAR *dpos, 
                    ULONG *dlen, 
                    PUCHAR *epos, 
                    ULONG *elen)
{
  SshUInt32 code, id, type, datalen;
  PUCHAR start, data;

  if (!ssh_wan_decode_cp_header(dpos, dlen, &code, &id, &datalen))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IPCP packet"));
      return FALSE;
    }

  if (code != SSH_PPP_CODE_CONFIGURE_REQUEST)
    return FALSE;

  /* Write initial header with zero length. */
  start = *epos;
  if (!ssh_wan_encode_cp_header(epos, elen,
                                SSH_PPP_CODE_CONFIGURE_REJECT, id, 0))
    return FALSE;
  data = *epos;

  while (ssh_wan_decode_option_header(dpos, dlen, &type, &datalen))
    {
      if (type == SSH_PPP_OPTION_IP_COMPRESSION_PROTOCOL)
        {
          if (!ssh_wan_encode_option_header(epos, elen, type, datalen) ||
              !ssh_wan_encode_data(epos, elen, *dpos, datalen))
            return FALSE;
        }
      ssh_wan_decode_skip(dpos, dlen, datalen);
    }

  /* Check if any options were rejected. */
  if (*epos == data)
    return FALSE;

  /* Set correct length. */
  ssh_wan_set_cp_length(start, *epos);
  return TRUE;
}


/*--------------------------------------------------------------------------
  Inspects an IPCP packet received from a WAN adapter. If it is a
  Configure-Request containing unwanted options, rejects it by sending
  an IPCP Configure-Reject to the WAN adapter and returns
  TRUE. Returns TRUE also if the IPCP packet is invalid or another
  error occurs. Returns FALSE if the IPCP packet is valid and was not
  intercepted.
  --------------------------------------------------------------------------*/
static Boolean
ssh_wan_intercept_ipcp_receive(SshNdisIMAdapter adapter, 
                               PUCHAR buffer, 
                               ULONG length)
{
  PNDIS_WAN_PACKET wan_pkt;
  PUCHAR dpos = buffer, epos;
  ULONG dlen = length, elen;

  /* Allocate a buffer large enough to contain:
     - PPP header (max 4 octets)
     - IPCP packet as large as the received one (length octets) */
  wan_pkt = ssh_wan_alloc_buffer_send(adapter, 4 + length);
  if (wan_pkt == NULL)
    goto fail;

  epos = wan_pkt->CurrentBuffer;
  elen = wan_pkt->EndBuffer - wan_pkt->CurrentBuffer;

  /* Encode PPP header. */
  if (!ssh_wan_encode_ppp_header(&epos, &elen, SSH_PPP_PROTOCOL_IPCP4,
                                 adapter->ppp_send_flags))
    goto fail;

  /* Scan the packet for any options that should be rejected and build
     a reject packet. Return FALSE if nothing rejected. */
  if (!ssh_wan_ipcp_reject(&dpos, &dlen, &epos, &elen))
    {
      ssh_wan_free_buffer_send(wan_pkt);
      return FALSE;
    }

  /* Send reject. */
  SSH_DEBUG(SSH_D_HIGHSTART, ("Sending IPCP Configure-Reject to adapter"));
  wan_pkt->CurrentLength = epos - wan_pkt->CurrentBuffer;
  ssh_wan_send_buffer(adapter, wan_pkt);
  return TRUE;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("Cannot send IPCP Configure-Reject"));
  if (wan_pkt)
    ssh_wan_free_buffer_send(wan_pkt);
  return TRUE;
}


/*--------------------------------------------------------------------------
  Inspects an IPCP packet sent to a WAN adapter. If it is a
  Configure-Request containing unwanted options, rejects it by
  indicating an IPCP Configure-Reject to the WAN protocol and returns
  TRUE. Returns TRUE also if the IPCP packet is invalid or another
  error occurs. Returns FALSE if the IPCP packet is valid and was not
  intercepted.
 --------------------------------------------------------------------------*/
static Boolean
ssh_wan_intercept_ipcp_send(SshNdisIMAdapter adapter, 
                            PUCHAR buffer, 
                            ULONG length)
{
  PUCHAR reject_buf, dpos = buffer, epos;
  ULONG reject_len, dlen = length, elen;

  /* Allocate a buffer large enough to contain:
     - PPP header (max 4 octets)
     - IPCP packet as large as the received one (length octets) */
  reject_len = 4 + length;
  reject_buf = ssh_wan_alloc_buffer_receive(adapter, reject_len);
  if (reject_buf == NULL)
    goto fail;

  epos = reject_buf;
  elen = reject_len;

  /* Encode PPP header. */
  if (!ssh_wan_encode_ppp_header(&epos, &elen, SSH_PPP_PROTOCOL_IPCP4,
                                 adapter->ppp_receive_flags))
    goto fail;

  /* Scan the packet for any options that should be rejected and build
     a reject packet. Return FALSE if nothing rejected. */
  if (!ssh_wan_ipcp_reject(&dpos, &dlen, &epos, &elen))
    {
      ssh_wan_free_buffer_receive(reject_buf);
      return FALSE;
    }

  /* Send reject. */
  SSH_DEBUG(SSH_D_HIGHSTART, ("Sending IPCP Configure-Reject to protocol"));
  ssh_wan_receive_buffer(adapter, reject_buf, epos - reject_buf);
  NdisMWanIndicateReceiveComplete(adapter->handle,adapter->wan_link_context);
  return TRUE;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("Cannot send IPCP Configure-Reject"));
  if (reject_buf)
    ssh_wan_free_buffer_receive(reject_buf);
  return TRUE;
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/


void
ssh_wan_free_buffer_send(PNDIS_WAN_PACKET wan_pkt)
{
  SshWanSendBufferHeader buf_hdr;

  /* Get the pointer to the allocated buffer and free. */
  buf_hdr = 
    CONTAINING_RECORD(wan_pkt, SshWanSendBufferHeaderStruct, wan_pkt);

  ssh_wan_free_buffer(buf_hdr->interceptor, buf_hdr->buffer);
}


Boolean
ssh_wan_intercept_from_protocol(SshNdisIMAdapter adapter, 
                                PNDIS_WAN_PACKET packet,
                                SshInterceptorProtocol *protocol)
{
  PUCHAR decode_pos = packet->CurrentBuffer;
  ULONG decode_len = packet->CurrentLength;
  SshUInt32 ppp_proto, flags;

  /* Get PPP header. */
  if (!ssh_wan_decode_ppp_header(&decode_pos, &decode_len, &ppp_proto,&flags))
    {
      SSH_DEBUG(SSH_D_FAIL, ("invalid PPP frame"));
      return FALSE;
    }

  /* Update PPP header compression flags. These will affect all
   * packets sent to the WAN adapter after processing in the engine. */
  adapter->ppp_send_flags = flags;

  switch (ppp_proto)
    {
    case SSH_PPP_PROTOCOL_IP4:
      *protocol = SSH_PROTOCOL_IP4;
      break;
    case SSH_PPP_PROTOCOL_IP6:
      *protocol = SSH_PROTOCOL_IP6;
      break;
    default:
      return FALSE;
    }

  /* Trim off PPP header */
  packet->CurrentBuffer = decode_pos;
  packet->CurrentLength = decode_len;
  return TRUE;
}


void
ssh_wan_process_from_protocol(SshNdisIMAdapter adapter, 
                              PNDIS_WAN_PACKET packet,
                              PNDIS_STATUS status)
{
  PUCHAR decode_pos = packet->CurrentBuffer;
  ULONG decode_len = packet->CurrentLength;
  SshUInt32 protocol, flags;
  PNDIS_WAN_PACKET copy;

  /* Get PPP header. */
  if (!ssh_wan_decode_ppp_header(&decode_pos, &decode_len, &protocol, &flags))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid PPP frame"));
      *status = NDIS_STATUS_FAILURE;
      return;
    }

  /* Reject compression/encryption negotiation. */
  if (protocol == SSH_PPP_PROTOCOL_CCP || protocol == SSH_PPP_PROTOCOL_ECP)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Rejecting CCP/ECP frame"));
      ssh_wan_reject_protocol_send(adapter, protocol, decode_pos, decode_len);
      *status = NDIS_STATUS_SUCCESS;
      return;
    }

  /* Reject IP-level compression/encryption. */
  if (protocol == SSH_PPP_PROTOCOL_IPCP4)
    {
      if (ssh_wan_intercept_ipcp_send(adapter, decode_pos, decode_len))
        {
          SSH_DEBUG(SSH_D_LOWSTART, ("Intercepted IPCP frame"));
          *status = NDIS_STATUS_SUCCESS;
          return;
        }
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Passing PPP frame through"));

  /* Pass other protocols through. Allocate a new buffer in this case
     too, in order to make proper SendComplete handling
     possible. Store pointer to the original packet in
     ProtocolReserved1 to cause a SendComplete to be sent to the
     protocol after a possible pending send. */
  if (!(copy = ssh_wan_alloc_buffer_send(adapter, packet->CurrentLength)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate packet buffer"));
      *status = NDIS_STATUS_FAILURE;
      return;
    }
  memcpy(copy->CurrentBuffer, packet->CurrentBuffer,packet->CurrentLength);
  copy->CurrentLength = packet->CurrentLength;
  copy->ProtocolReserved1 = packet;
  WanMiniportSend(status, adapter->binding_handle,
                  adapter->wan_link_handle, copy);
}


Boolean
ssh_wan_intercept_from_adapter(SshNdisIMAdapter adapter,
                               PUCHAR *packet, 
                               ULONG *packet_size,
                               SshInterceptorProtocol *protocol)
{
  PUCHAR decode_pos = *packet;
  ULONG decode_len = *packet_size;
  SshUInt32 ppp_proto, flags;

  /* Get PPP header. */
  if (!ssh_wan_decode_ppp_header(&decode_pos, &decode_len, &ppp_proto, &flags))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid PPP frame"));
      return FALSE;
    }

  /* Update PPP header compression flags. These will affect all
   * packets sent to the protocol after processing in the engine. */
  adapter->ppp_receive_flags = flags;

  switch (ppp_proto)
    {
    case SSH_PPP_PROTOCOL_IP4:
      *protocol = SSH_PROTOCOL_IP4;
      break;
    case SSH_PPP_PROTOCOL_IP6:
      *protocol = SSH_PROTOCOL_IP6;
      break;
    default:
      return FALSE;
    }

  /* Trim off PPP header */
  *packet = decode_pos;
  *packet_size = decode_len;
  return TRUE;
}


void
ssh_wan_process_from_adapter(SshNdisIMAdapter adapter,
                             PUCHAR packet, 
                             ULONG packet_size,
                             PNDIS_STATUS status)
{
  PUCHAR decode_pos = packet;
  ULONG decode_len = packet_size;
  SshUInt32 protocol, flags;

  /* Get PPP header. */
  if (!ssh_wan_decode_ppp_header(&decode_pos, &decode_len, &protocol, &flags))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid PPP frame"));
      *status = NDIS_STATUS_FAILURE;
      return;
    }

  /* Reject compression/encryption negotiation. */
  if (protocol == SSH_PPP_PROTOCOL_CCP || protocol == SSH_PPP_PROTOCOL_ECP)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Rejecting CCP/ECP"));
      ssh_wan_reject_protocol_receive(adapter, protocol,
                                      decode_pos, decode_len);
      *status = NDIS_STATUS_SUCCESS;
      return;
    }

  /* Reject IP-level compression/encryption. */
  if (protocol == SSH_PPP_PROTOCOL_IPCP4)
    {
      if (ssh_wan_intercept_ipcp_receive(adapter, decode_pos, decode_len))
        {
          SSH_DEBUG(SSH_D_LOWSTART, ("Intercepted IPCP frame"));
          *status = NDIS_STATUS_SUCCESS;
          return;
        }
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Passing PPP frame through"));

  /* Pass other protocols through. */
  NdisMWanIndicateReceive(status, adapter->handle,
                          adapter->wan_link_context,
                          packet, packet_size);
  return;
}


Boolean
ssh_wan_send_to_adapter(SshNdisIMAdapter adapter, 
                        SshNdisPacket packet,
                        SshInterceptorProtocol protocol)
{
  UINT pkt_len;
  SshUInt32 ppp_protocol;
  PUCHAR pos;
  ULONG len;
  PNDIS_WAN_PACKET wan_pkt;

  switch (protocol)
    {
    case SSH_PROTOCOL_IP4:
      ppp_protocol = SSH_PPP_PROTOCOL_IP4;
      break;
    case SSH_PROTOCOL_IP6:
      ppp_protocol = SSH_PPP_PROTOCOL_IP6;
      break;
    default:
      SSH_DEBUG(SSH_D_ERROR, ("Cannot PPP-encapsulate non-IP protocol"));
      return FALSE;
    }

  NdisQueryPacket(packet->np, NULL, NULL, NULL, &pkt_len);

  /* Allocate a buffer large enough a PPP header and the packet. */
  if (!(wan_pkt = ssh_wan_alloc_buffer_send(adapter, 4 + pkt_len)))
    goto fail;

  pos = wan_pkt->CurrentBuffer;
  len = 4 + pkt_len;

  /* Create PPP header. */
  if (!ssh_wan_encode_ppp_header(&pos, &len, ppp_protocol,
                                 adapter->ppp_send_flags))
    goto fail;

  /* Add the packet itself. */
  ssh_interceptor_packet_copyout(&packet->ip, 0, pos, pkt_len);
  pos += pkt_len;
  len -= pkt_len;

  wan_pkt->CurrentLength = pos - wan_pkt->CurrentBuffer;

  /* Send WAN packet to adapter. */
  ssh_wan_send_buffer(adapter, wan_pkt);
  return TRUE;

 fail:
  if (wan_pkt)
    ssh_wan_free_buffer_send(wan_pkt);
  return FALSE;
}


Boolean
ssh_wan_send_to_protocol(SshNdisIMAdapter adapter, 
                         SshNdisPacket packet,
                         SshInterceptorProtocol protocol)
{
  UINT pkt_len;
  SshUInt32 ppp_protocol;
  PUCHAR buffer, pos;
  ULONG len;

  switch (protocol)
    {
    case SSH_PROTOCOL_IP4:
      ppp_protocol = SSH_PPP_PROTOCOL_IP4;
      break;
    case SSH_PROTOCOL_IP6:
      ppp_protocol = SSH_PPP_PROTOCOL_IP6;
      break;
    default:
      SSH_DEBUG(SSH_D_ERROR, ("Cannot PPP-encapsulate non-IP protocol"));
      return FALSE;
    }

  NdisQueryPacket(packet->np, NULL, NULL, NULL, &pkt_len);

  /* Allocate a buffer large enough a PPP header and the packet. */
  buffer = ssh_wan_alloc_buffer_receive(adapter, 4 + pkt_len);
  if (buffer == NULL)
    goto fail;

  pos = buffer;
  len = 4 + pkt_len;

  /* Create PPP header. */
  if (!ssh_wan_encode_ppp_header(&pos, &len, ppp_protocol,
                                adapter->ppp_receive_flags))
    goto fail;

  /* Add the packet itself. */
  ssh_interceptor_packet_copyout(&packet->ip, 0, pos, pkt_len);
  pos += pkt_len;
  len -= pkt_len;

  /* Indicate WAN packet to protocol. */
  ssh_wan_receive_buffer(adapter, buffer, pos - buffer);
  return TRUE;

 fail:
  if (buffer)
    ssh_wan_free_buffer_receive(buffer);
  return FALSE;
}
#endif /* _WIN32_WCE */
