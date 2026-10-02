/*
 * SPRD USB to serial adaptor driver
 *
 * Copyright (C) 2001-2010 Rocky Liao (rocky.liao@spreadtrum.com)
 * Copyright (C) 2003 Spreadtrum Communication Corp.
 *
 */
#ifndef __SPRD_U2S_H
#define __SPRD_U2S_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 15)
#define KERNEL_VERSION_ABOVE_2_6_15
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
#define KERNEL_VERSION_ABOVE_2_6_16
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
#define KERNEL_VERSION_ABOVE_2_6_18
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21)
#define KERNEL_VERSION_ABOVE_2_6_21
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
#define KERNEL_VERSION_ABOVE_2_6_26
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
#define KERNEL_VERSION_ABOVE_2_6_31
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define KERNEL_VERSION_ABOVE_2_6_32
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
#define KERNEL_VERSION_ABOVE_3_5_0
#endif

#if defined KERNEL_VERSION_ABOVE_3_5_0
#include <asm/uaccess.h>
//#include "usb-serial.h"
#include <linux/usb/serial.h>
#elif defined KERNEL_VERSION_ABOVE_2_6_18
#include <linux/uaccess.h>
#include <linux/usb/serial.h>
#else
#include <asm/uaccess.h>
#include "usb-serial.h"
#endif

#define SPRD_VID                0x1782
#define SPRD_PID_DIAG           0x4d00
#define SPRD_PID_DIAG_MODEM     0x3d00
#define SPRD_PID_MODEM          0x3d01
#define SPRD_PID_MODEM_CDROM    0x3d02
#define SPRD_PID_7702_DATACARD  0x0003

#define SPRD_VENDOR_CMD         0x22
#define TODEV_INIT              0x00
#define TODEV_CREATE 	          0x01
#define TODEV_CLOSE 	          0x02

#define URB_TIMEOUT 5000 // 5000 microseconds

struct sprd_private {
	int reserved;

};
#endif

#ifdef KERNEL_VERSION_ABOVE_3_5_0
#else
static int sprd_u2s_usb_probe(struct usb_interface *interface,
			       const struct usb_device_id *id);

static void sprd_u2s_usb_disconnect(struct usb_interface *interface);

#endif

#ifdef KERNEL_VERSION_ABOVE_2_6_26

#ifdef KERNEL_VERSION_ABOVE_2_6_31
static void sprd_u2s_close(struct usb_serial_port *port);
#else
static void sprd_u2s_close(struct tty_struct *tty,
			                     struct usb_serial_port *port, struct file *filp);
#endif // KERNEL_VERSION_ABOVE_2_6_31

#ifdef KERNEL_VERSION_ABOVE_2_6_32
static int sprd_u2s_open(struct tty_struct *tty,
			                   struct usb_serial_port *port);
#else
static int sprd_u2s_open(struct tty_struct *tty,
			                   struct usb_serial_port *port, struct file *filp);
#endif // KERNEL_VERSION_ABOVE_2_6_32

#else  // KERNEL_VERSION < 2.6.26
static int sprd_u2s_open(struct usb_serial_port *port, 
			                   struct file *filp);

static void sprd_u2s_close(struct usb_serial_port *port,
			                     struct file *filp);
#endif // KERNEL_VERSION_ABOVE_2_6_26

/*

static void sprd_u2s_read_bulk_callback(struct urb *urb);

static void sprd_u2s_resubmit_read_urb(struct usb_serial_port *port,
			gfp_t mem_flags);

static void sprd_u2s_flush_and_resubmit_read_urb(struct usb_serial_port *port);

static void sprd_u2s_write_bulk_callback(struct urb *urb);

static void sprd_u2s_cleanup(struct usb_serial_port *port);

#ifdef SPRD_KERNEL_VERSION_ABOVE_2_6_28
static int sprd_u2s_write(struct tty_struct *tty,
	struct usb_serial_port *port, const unsigned char *buf, int count);

static int sprd_u2s_write_room(struct tty_struct *tty);

static int sprd_u2s_chars_in_buffer(struct tty_struct *tty);

static int sprd_u2s_open(struct tty_struct *tty,
			struct usb_serial_port *port, struct file *filp);

#ifdef SPRD_KERNEL_VERSION_ABOVE_2_6_31
static void sprd_u2s_close(struct usb_serial_port *port);
#else
static void sprd_u2s_close(struct tty_struct *tty,
			struct usb_serial_port *port, struct file *filp);

#endif

//static void sprd_u2s_port_disconnect(struct usb_serial *serial);

//static int sprd_u2s_port_attach(struct usb_serial *serial);

//static void sprd_u2s_port_release(struct usb_serial *serial);

static void sprd_u2s_throttle(struct tty_struct *tty);

static void sprd_u2s_unthrottle(struct tty_struct *tty);
#else
static int  sprd_u2s_open(struct usb_serial_port *port, struct file * filp);

static void sprd_u2s_close(struct usb_serial_port *port, struct file * filp);

static int  sprd_u2s_write(struct usb_serial_port *port, const unsigned char *buf, int count);

static int  sprd_u2s_write_room(struct usb_serial_port *port);

static int  sprd_u2s_chars_in_buffer(struct usb_serial_port *port);

static void sprd_u2s_throttle(struct usb_serial_port *port);

static void sprd_u2s_unthrottle(struct usb_serial_port *port);
#endif

#endif
*/
