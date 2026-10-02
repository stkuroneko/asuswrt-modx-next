#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>

static char *nic = NULL;
module_param(nic, charp, 0);

static struct dupvif_info {
	struct net_device *dev;
	struct net_device *org_dev;
	struct net_device_stats stats;
} vif;

extern int (*hijack_rx)(struct sk_buff *skb);
extern struct net_device *hijack_dev;

static unsigned char bcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static int dupvif_net_recv(struct sk_buff *skb)
{
	unsigned char *mac_pt;
	unsigned short eth_type;
	int filter_to_dup = 0;

	if (skb->dev == NULL || skb->dev != vif.org_dev)
		return 0;
	mac_pt = skb_mac_header(skb);
	if (mac_pt == NULL)
		return 0;
	eth_type = ntohs(*((unsigned short *)(mac_pt+12)));
	if (eth_type == ETH_P_PPP_SES || eth_type == ETH_P_PPP_DISC) // PPPoE
		filter_to_dup = 1;
	else if (memcmp(vif.dev->dev_addr, mac_pt, 6) == 0) // to dup's MAC
		filter_to_dup = 1;
	else if (memcmp(bcast_mac, mac_pt, 6) == 0 && eth_type == ETH_P_ARP) { // broadcast ARP
		struct sk_buff *skb2;
	        skb2 = skb_clone(skb, GFP_ATOMIC);
		if (!skb2)
			return 0;
		filter_to_dup = 2;
		skb = skb2;
	}

	if (filter_to_dup == 0)
		return 0;

	skb->dev = vif.dev;
	skb->pkt_type=0;
	vif.stats.rx_packets++;
	vif.stats.rx_bytes += skb->len;
	netif_rx_ni(skb);
	if (filter_to_dup & 1)
		return 1; // hijack
	else
		return 0; // duplicated, let original skb go
}

static int dupvif_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	if (!(vif.org_dev->flags & IFF_UP))
		goto drop;
	skb->dev = vif.org_dev;
	skb->priority = 0;
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, sizeof (struct ethhdr));
	dev_queue_xmit(skb);
	vif.stats.tx_packets++;
	vif.stats.tx_bytes += skb->len;
	return 0;
drop:
	vif.stats.tx_dropped++;
	return 0;
}

static int dupvif_net_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int dupvif_net_close(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static void dupvif_net_mclist(struct net_device *dev)
{
	return;
}

static struct net_device_stats *dupvif_net_stats(struct net_device *dev)
{
	return &vif.stats;
}

static int dupvif_net_init(struct net_device *dev)
{
	return 0;
}

static const struct net_device_ops netop = {
	.ndo_init = dupvif_net_init,
	.ndo_open = dupvif_net_open,
	.ndo_start_xmit = dupvif_net_xmit,
	.ndo_stop = dupvif_net_close,
	.ndo_get_stats = dupvif_net_stats,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_set_rx_mode = dupvif_net_mclist,
};

int __init dupvif_init(void)
{
	struct net_device *dev;
	struct net_device *org_dev;

	if (nic == NULL) {
		printk(KERN_ERR "No target nic name!!\n");
		return -1;
	}

	rtnl_lock();
	org_dev = __dev_get_by_name(&init_net, nic);
	rtnl_unlock();

	if (!org_dev) {
		printk(KERN_ERR "NIC[%s] not found!!\n", nic);
		return -1;
	}

	dev = alloc_etherdev(0);
	if (dev == NULL) {
		printk(KERN_ERR "alloc_etherdev fail!\n");
		return -1;
	}
	dev->dev_addr[0] = org_dev->dev_addr[0] | 0x2;
	dev->dev_addr[1] = org_dev->dev_addr[1];
	dev->dev_addr[2] = org_dev->dev_addr[2];
	//eth_hw_addr_random(dev);
	get_random_bytes(dev->dev_addr+3, 3);

	memset(&vif, 0, sizeof(struct dupvif_info));
	vif.dev = dev;
	vif.org_dev = org_dev;
	snprintf(dev->name, sizeof(dev->name), "%s_dup", nic);

	printk(KERN_CRIT "dupvif: dup name:%s, mac:%pM\n", dev->name, dev->dev_addr);
	rtnl_lock();
	ether_setup(dev);
	dev->netdev_ops = &netop;
	if (register_netdevice(dev)) {
		rtnl_unlock();
		free_netdev(dev);
		return -1;
	}
	hijack_rx = dupvif_net_recv;
	hijack_dev = org_dev ;
	rtnl_unlock();
	return 0;
}

void dupvif_cleanup(void)
{
	hijack_rx = NULL;
	hijack_dev = NULL;
	rtnl_lock();
	dev_close(vif.dev);
	unregister_netdevice(vif.dev);
	rtnl_unlock();
}

module_init(dupvif_init);
module_exit(dupvif_cleanup);
MODULE_LICENSE("Proprietary");
