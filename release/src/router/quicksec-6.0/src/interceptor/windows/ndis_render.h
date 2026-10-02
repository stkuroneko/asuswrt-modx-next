/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   NDIS data type renderer related functions and definitions.
*/

#ifndef SSH_NDIS_RENDER_H
#define SSH_NDIS_RENDER_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef DEBUG_LIGHT
/* Render function to render NDIS OIDs for %@ format string for
   ssh_e*printf */
int ssh_ndis_oid_render(unsigned char *buf,
                        int buf_size,
                        int precision,
                        void *datum);

/* Render function to render NDIS OID REQUEST types for %@ format string for
   ssh_e*printf */
int ssh_ndis_oid_request_type_render(unsigned char *buf,
                                     int buf_size,
                                     int precision,
                                     void *datum);

/* Render function to render NDIS_STATUS_XXX values for %@ format string
   for ssh_e*printf */
int ssh_ndis_status_render(unsigned char *buf, 
                           int buf_size, 
                           int precision,
                           void *datum);
#ifdef _WIN32_WCE
/* Render functions to render NDIS Wireless WAN data types for %@ format
   string for ssh_e*printf. */
int ssh_ndis_ww_notification_type_render(unsigned char *buf,
                                         int buf_size,
                                         int precision,
                                         void *datum);
#endif /* _WIN32_WCE */

/* Render function to render NDIS packet filter bit fields for %@ format 
   string for ssh_e*printf */
int ssh_ndis_packet_filter_bits_render(unsigned char *buf, 
                                       int buf_size, 
                                       int precision,
                                       void *datum);

#ifdef NDIS60

/* Render function to render NDIS 6.x send flags for %@ format string 
   for ssh_e*printf */
int ssh_ndis_send_flags_render(unsigned char *buf, 
                               int buf_size, 
                               int precision,
                               void *datum);

/* Render function to render NDIS 6.x send complete flags for %@ format 
   string for ssh_e*printf */
int ssh_ndis_send_complete_flags_render(unsigned char *buf, 
                                        int buf_size, 
                                        int precision,
                                        void *datum);

/* Render function to render NDIS 6.x receive flags for %@ format 
   string for ssh_e*printf */
int ssh_ndis_receive_flags_render(unsigned char *buf, 
                                  int buf_size, 
                                  int precision,
                                  void *datum);

/* Render function to render NDIS 6.x return (i.e. receive complete) 
   flags for %@ format string for ssh_e*printf */
int ssh_ndis_return_flags_render(unsigned char *buf, 
                                 int buf_size, 
                                 int precision,
                                 void *datum);
#endif /* NDIS60 */

#endif /* DEBUG_LIGHT */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_NDIS_OID_RENDER_H */
