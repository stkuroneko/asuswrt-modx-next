/*
 * SPRD USB to serial adaptor driver
 *
 * Copyright (C) 2001-2010 Rocky Liao (rocky.liao@spreadtrum.com)
 * Copyright (C) 2003 Spreadtrum Communication Corp.
 *
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
//#include <linux/smp_lock.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/usb.h>
//#include <linux/serial.h>

#include "sprdu2s.h"

/*
 * Version Information
 */
#define DRIVER_VERSION "v1.0.0"
#define DRIVER_AUTHOR  "Rocky Liao<rocky.liao@spreadtrum.com>"
#define DRIVER_DESC    "SPRD USB Serial Converters Driver"
#define USE_IMMEDIATE

static int debug;

static struct usb_device_id sprd_id_table[] = {
    { USB_DEVICE(SPRD_VID, SPRD_PID_DIAG) },
    { USB_DEVICE(SPRD_VID, SPRD_PID_DIAG_MODEM) },
    { USB_DEVICE(SPRD_VID, SPRD_PID_MODEM) },
    { USB_DEVICE(SPRD_VID, SPRD_PID_MODEM_CDROM) },
    { USB_DEVICE(SPRD_VID, SPRD_PID_7702_DATACARD) },
    {}
};

MODULE_DEVICE_TABLE(usb, sprd_id_table);

static struct usb_driver sprd_u2s_driver = {
	.name          = "sprd_usb",
#ifndef KERNEL_VERSION_ABOVE_3_5_0
	.probe         = sprd_u2s_usb_probe,
	.disconnect    = sprd_u2s_usb_disconnect,
#endif
	.id_table      = sprd_id_table,
	//.suspend     = sprd_u2s_suspend,
	//.resume      = sprd_u2s_resume,
	#ifdef KERNEL_VERSION_ABOVE_2_6_16
	.no_dynamic_id = 1,
	#endif
	//.supports_autosuspend = 1,
};

#if defined KERNEL_VERSION_ABOVE_2_6_15
/* All of the device info needed for the sprd usb-serial converter */
static struct usb_serial_driver sprd_u2s_device = {
	.driver = {
		.owner = THIS_MODULE,
		.name  = "sprd_u2s",
	},
	.id_table   = sprd_id_table,
	#ifdef KERNEL_VERSION_ABOVE_2_6_21
	.usb_driver = &sprd_u2s_driver,
	#endif
	.num_ports  = 1,
	.open       = sprd_u2s_open,
	.close      = sprd_u2s_close,
};

static struct usb_serial_driver sprd_generic_u2s_interface = {
	.driver = {
		.owner = THIS_MODULE,
		.name  = "sprd_generic_u2s_interface",
	},
	#ifdef KERNEL_VERSION_ABOVE_2_6_21
	.usb_driver = &sprd_u2s_driver,
	#endif
};

#ifdef KERNEL_VERSION_ABOVE_3_5_0
static struct usb_serial_driver *sprd_u2s[]={	
	&sprd_generic_u2s_interface,
	&sprd_u2s_device,
	NULL
};
#endif


#else
/* All of the device info needed for the sprd usb-serial converter */
static struct usb_serial_device_type sprd_u2s_device = {
	.owner     = THIS_MODULE,
	.name      = "sprd_u2s",
	.id_table  = sprd_id_table,
	.num_ports = 1,
	.open      = sprd_u2s_open,
	.close     = sprd_u2s_close,
};

static struct usb_serial_device_type sprd_generic_u2s_interface = {
	.owner = THIS_MODULE,
	.name  = "sprd_generic_u2s_interface",
};

#endif

#ifndef KERNEL_VERSION_ABOVE_3_5_0
static int sprd_u2s_usb_probe(struct usb_interface *interface,
			       const struct usb_device_id *id)
{
	const struct usb_device_id *id_pattern;
	struct usb_device *dev = interface_to_usbdev(interface);
	int retval;
	//static int interface_id = 0;

	dbg("%s: ++: interface->minor = %d", __func__, interface->minor);

	id_pattern = usb_match_id(interface, sprd_id_table);
	if (id_pattern != NULL) {
		retval = usb_control_msg(dev,
					usb_sndctrlpipe(dev, 0),
					SPRD_VENDOR_CMD,
					USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
					TODEV_INIT,
					0,
					NULL,
					0,
					URB_TIMEOUT
					);
		if (retval) {
			//dev_err(&dev->dev, "%s: Init device failed", __func__);
			return retval;
		}
		return usb_serial_probe(interface, id);
	}

	dbg("%s: --. not match", __func__);
	return -ENODEV;
}

static void sprd_u2s_usb_disconnect(struct usb_interface *interface)
{	
	dbg("%s: ++", __func__);
	usb_serial_disconnect(interface);
}
#endif

#if defined KERNEL_VERSION_ABOVE_3_5_0
	static void sprd_u2s_close(struct usb_serial_port *port)
	{
		struct usb_serial *serial = port->serial;
		unsigned short value = port->bulk_in_endpointAddress & 0xF;
		int result;

		//dbg("%s:++ port %d", __func__, port->port_number);

		sprd_generic_u2s_interface.close(port);
		
		//hongliang, not send SPRD_VENDOR_CMD		
		//dbg("%s:--", __func__);		
		return;

    /*
		value = (value << 8) | TODEV_INIT;

		dbg("%s:value = %04x", __func__, value);

		result = usb_control_msg(serial->dev,
					usb_sndctrlpipe(serial->dev, 0),
					SPRD_VENDOR_CMD,
					USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
					value,
					0,
					NULL,
					0,
					URB_TIMEOUT
					);
		if (result) {
			dev_err(&port->dev, "%s: Send vendor close command failed", __func__);
		}

		dbg("%s:--", __func__);
		*/

	}

	static int sprd_u2s_open(struct tty_struct *tty,
				struct usb_serial_port *port)
	{
		struct usb_serial *serial = port->serial;
		int result = 0;
		unsigned short value = port->bulk_out_endpointAddress;

		//dbg("%s: ++. port %d", __func__, port->port_number);

		value = value << 8 | TODEV_CREATE;

//		dbg("%s:value = %04x", __func__, value);

		result = usb_control_msg(serial->dev,
					usb_sndctrlpipe(serial->dev, 0),
					SPRD_VENDOR_CMD,
					USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
					value,
					0,
					NULL,
					0,
					URB_TIMEOUT
					);
		if (result) {
			//dev_err(&port->dev, "%s: Send vendor open command failed", __func__);
			return result;
		}
 
		result = sprd_generic_u2s_interface.open(tty, port);

		return result;
	}


#elif defined KERNEL_VERSION_ABOVE_2_6_26

	#ifdef KERNEL_VERSION_ABOVE_2_6_31
	static void sprd_u2s_close(struct usb_serial_port *port)
	{
		struct usb_serial *serial = port->serial;
		unsigned short value = port->bulk_in_endpointAddress & 0xF;
		int result;

		dbg("%s:++ port %d", __func__, port->number);

		sprd_generic_u2s_interface.close(port);
		
		//hongliang, not send SPRD_VENDOR_CMD		
		dbg("%s:--", __func__);		
		return;

    /*
		value = (value << 8) | TODEV_INIT;

		dbg("%s:value = %04x", __func__, value);

		result = usb_control_msg(serial->dev,
					usb_sndctrlpipe(serial->dev, 0),
					SPRD_VENDOR_CMD,
					USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
					value,
					0,
					NULL,
					0,
					URB_TIMEOUT
					);
		if (result) {
			dev_err(&port->dev, "%s: Send vendor close command failed", __func__);
		}

		dbg("%s:--", __func__);
		*/

	}
	#else
	static void sprd_u2s_close(struct tty_struct *tty,
				struct usb_serial_port *port, struct file *filp)
	{
		struct usb_serial *serial = port->serial;
		unsigned short value = port->bulk_in_endpointAddress & 0xF;
		int result;

		dbg("%s:++ port %d", __func__, port->number);

		sprd_generic_u2s_interface.close(tty, port, filp);

		value = (value & 0x7F)<< 8 | TODEV_INIT;

		dbg("%s:value = %04x", __func__, value);

		result = usb_control_msg(serial->dev,
					usb_sndctrlpipe(serial->dev, 0),
					SPRD_VENDOR_CMD,
					USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
					value,
					0,
					NULL,
					0,
					URB_TIMEOUT
					);
		if (result) {
			//dev_err(&port->dev, "%s: Send vendor close command failed", __func__);
		}
		dbg("%s:--", __func__);

	}
	#endif

	#ifdef KERNEL_VERSION_ABOVE_2_6_32
	static int sprd_u2s_open(struct tty_struct *tty,
				struct usb_serial_port *port)
	{
		struct usb_serial *serial = port->serial;
		int result = 0;
		unsigned short value = port->bulk_out_endpointAddress;

		dbg("%s: ++. port %d", __func__, port->number);

		value = value << 8 | TODEV_CREATE;

		dbg("%s:value = %04x", __func__, value);

		result = usb_control_msg(serial->dev,
					usb_sndctrlpipe(serial->dev, 0),
					SPRD_VENDOR_CMD,
					USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
					value,
					0,
					NULL,
					0,
					URB_TIMEOUT
					);
		if (result) {
			//dev_err(&port->dev, "%s: Send vendor open command failed", __func__);
			return result;
		}
 
		result = sprd_generic_u2s_interface.open(tty, port);

		return result;
	}

	#else
	static int sprd_u2s_open(struct tty_struct *tty,
				struct usb_serial_port *port, struct file *filp)
	{
		struct usb_serial *serial = port->serial;
		int result = 0;
		unsigned short value = port->bulk_out_endpointAddress;

		dbg("%s: ++. port %d", __func__, port->number);

		value = value << 8 | TODEV_CREATE;

		dbg("%s:value = %04x", __func__, value);

		result = usb_control_msg(serial->dev,
					usb_sndctrlpipe(serial->dev, 0),
					SPRD_VENDOR_CMD,
					USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
					value,
					0,
					NULL,
					0,
					URB_TIMEOUT
					);
		if (result) {
			//dev_err(&port->dev, "%s: Send vendor open command failed", __func__);
			return result;
		}

		result = sprd_generic_u2s_interface.open(tty, port, filp);

		return result;
	}
	#endif

#else  // kernel version < 2.6.26
	static int sprd_u2s_open(struct usb_serial_port *port, 
				struct file *filp)
	{
		struct usb_serial *serial = port->serial;
		int result = 0;
		unsigned short value = port->bulk_out_endpointAddress;

		dbg("%s: ++. port %d", __func__, port->number);

		value = value << 8 | TODEV_CREATE;

		dbg("%s:value = %04x", __func__, value);

		result = usb_control_msg(serial->dev,
					usb_sndctrlpipe(serial->dev, 0),
					SPRD_VENDOR_CMD,
					USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
					value,
					0,
					NULL,
					0,
					URB_TIMEOUT
					);
		if (result) {
			//dev_err(&port->dev, "%s: Send vendor open command failed", __func__);
			return result;
		}

		result = sprd_generic_u2s_interface.open(port, filp);

		return result;
	}

	static void sprd_u2s_close(struct usb_serial_port *port,
					struct file *filp)
	{
		struct usb_serial *serial = port->serial;
		unsigned short value = port->bulk_in_endpointAddress & 0xF;
		int result;

		dbg("%s:++ port %d", __func__, port->number);

		sprd_generic_u2s_interface.close(port, filp);
		
		//hongliang, not send SPRD_VENDOR_CMD		
		dbg("%s:--", __func__);		
		return;
    /*
		value = (value << 8) | TODEV_INIT;

		dbg("%s:value = %04x", __func__, value);

		result = usb_control_msg(serial->dev,
							usb_sndctrlpipe(serial->dev, 0),
							SPRD_VENDOR_CMD,
							USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
							value,
							0,
							NULL,
							0,
							URB_TIMEOUT
							);
		if (result) {
			dev_err(&port->dev, "%s: Send vendor close command failed", __func__);
		}
		dbg("%s:--", __func__);	
		*/

	}

#endif

static int __init sprd_init(void)
{
	int retval;

	//dbg("%s: ++", __func__);

#ifndef KERNEL_VERSION_ABOVE_3_5_0

	retval = usb_serial_register(&sprd_u2s_device);
	if (retval)
		goto failed_usb_serial_register;

  	retval = usb_serial_register(&sprd_generic_u2s_interface);
  	if (retval)
		goto failed_generic_u2s_interface_register;

	retval = usb_register(&sprd_u2s_driver);
	if (retval)
		goto failed_usb_register;

	//printk(KERN_INFO KBUILD_MODNAME ": " DRIVER_DESC "\n");
	dbg("%s: %s registered", __func__, DRIVER_DESC);
	return 0;	
  
failed_usb_register:
	dbg("%s: failed_usb_register", __func__);
	usb_serial_deregister(&sprd_generic_u2s_interface);
    
failed_generic_u2s_interface_register:
	dbg("%s: failed_generic_u2s_interface_register", __func__);
	usb_serial_deregister(&sprd_u2s_device);
    
failed_usb_serial_register:
	dbg("%s: failed_usb_serial_register", __func__);
	return retval;
#else
	retval = usb_serial_register_drivers(sprd_u2s,"sprd_u2s",sprd_id_table);
	return retval;
#endif 
}

static void __exit sprd_exit(void)
{
#ifndef KERNEL_VERSION_ABOVE_3_5_0
	usb_deregister(&sprd_u2s_driver);
	usb_serial_deregister(&sprd_generic_u2s_interface);
	usb_serial_deregister(&sprd_u2s_device);
#else
	usb_serial_deregister_drivers(sprd_u2s);
#endif
}

module_init(sprd_init);
module_exit(sprd_exit);

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Debug enabled or not");
