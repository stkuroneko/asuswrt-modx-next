/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 * 
 *   debug.h - Debugging Definitions and Declarations;
 *
 *   this file is a subset of the original that includes only those
 *   definitions and declaration needed for toolkit programs;
 *
 *--------------------------------------------------------------------*/

#ifndef DEBUG_HEADER
#define DEBUG_HEADER

/*====================================================================*
 *   constants;
 *--------------------------------------------------------------------*/

#define QUALCOMM_DEBUG 0
#define QUALCOMM_TRACE 0

/*====================================================================*
 *   
 *--------------------------------------------------------------------*/

#if QUALCOMM_TRACE
#define EVENT(s) printk(KERN_DEBUG "---[ %s ]---\n", (s))
#define ENTER printk(KERN_DEBUG "-->[ %s:%d ]\n", __func__,__LINE__)
#define ABORT printk(KERN_DEBUG "<--( %s:%d )\n", __func__,__LINE__)
#define LEAVE printk(KERN_DEBUG "<--[ %s:%d ]\n", __func__,__LINE__)
#define CRUMB printk(KERN_DEBUG "... %s:%d\n",__func__,__LINE__) 
#define TRACE error (0, 0, "%s (%d)", __FILE__, __LINE__);
#else
#define EVENT {}
#define ENTER {}
#define ABORT {}
#define LEAVE {}
#define CRUMB {}
#define TRACE {}
#endif

/*====================================================================*
 *   
 *--------------------------------------------------------------------*/

#if QUALCOMM_DEBUG
#define address(e) if (!(e)) { printk ("%s(%d): address %s is null\n",__func__,__LINE__,#e); }
#define confirm(e) if (!(e)) { printk ("%s(%d): assertion %s is wrong\n",__func__,__LINE__, #e); }
#else
#define address(e) {}
#define confirm(e) {}
#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



