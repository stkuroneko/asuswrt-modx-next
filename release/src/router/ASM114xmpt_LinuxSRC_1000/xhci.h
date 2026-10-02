#ifndef _XHCI_H_
#define _XHCI_H_


/**
 *
 */
struct xhci_cap_regs
{
    u32	hc_capbase;
    u32	hcs_params1;
    u32	hcs_params2;
    u32	hcs_params3;
    u32	hcc_params;
    u32	db_off;
    u32	run_regs_off;
    /* Reserved up to (CAPLENGTH - 0x1C) */
};

#define HC_LENGTH(p)    (((p)>>00)&0x00ff)
#define	RTSOFF_MASK	(~0x1f)
#define HCS_MAX_PORTS(p)	(((p) >> 24) & 0x7f)

/* Number of registers per port */
#define	NUM_PORT_REGS	4

/**
 *
 */
struct xhci_op_regs
{
    u32	command;
    u32	status;
    u32	page_size;
    u32	reserved1;
    u32	reserved2;
    u32	dev_notification;
    u64	cmd_ring;
    /* rsvd: offset 0x20-2F */
    u32	reserved3[4];
    u64	dcbaa_ptr;
    u32	config_reg;
    /* rsvd: offset 0x3C-3FF */
    u32	reserved4[241];
    /* port 1 registers, which serve as a base address for other ports */
    u32	port_status_base;
    u32	port_power_base;
    u32	port_link_base;
    u32	reserved5;
    /* registers for ports 2-255 */
    u32	reserved6[NUM_PORT_REGS*254];
};

struct xhci_hcd
{
    struct xhci_cap_regs *cap_regs;	//Host controller capability registers , xhci 0.96(Ch 5.3)
    struct xhci_op_regs *op_regs;		//Host Controller Operational Registers , xhci 0.96(Ch 5.4)
    u32 	hcs_params1;
    int 	fd;
};



#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)(n))



#endif  /* _XHCI_H_ */

