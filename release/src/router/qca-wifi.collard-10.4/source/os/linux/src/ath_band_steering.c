/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */
#include "linux/if.h"
#include "linux/socket.h"
#include "linux/netlink.h"
#include <net/sock.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/cache.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include "sys/queue.h"
#include "ath_band_steering.h"

#if ATH_BAND_STEERING

struct band_steering_netlink *band_steering_nl = NULL;

/**
 * @brief Send a unicast netlink message containing the band steering event.
 *
 * @param event  the structure containing all of the event data
 */
void ath_band_steering_netlink_send(ath_netlink_bsteering_event_t *event)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh;
    u_int8_t *nldata = NULL;
    u_int32_t pid;

    if (!band_steering_nl || !event) {
        return;
    }

    pid = band_steering_nl->bsteer_pid;
    if (WLAN_DEFAULT_BSTEER_NETLINK_PID == pid) {
        // No user space daemon has requested events yet, so drop it.
        return;
    }

    skb = nlmsg_new(sizeof(*event), GFP_ATOMIC);
    if (!skb) {
        printk("%s: No memory, event = %d\n", __func__, event->type);
        return;
    }

    nlh = nlmsg_put(skb, pid, 0, event->type, sizeof(*event), 0);
    if (!nlh) {
        printk("%s: nlmsg_put() failed, event = %d\n", __func__, event->type);
        kfree_skb(skb);
        return;
    }

    nldata = NLMSG_DATA(nlh);
    memcpy(nldata, event, sizeof(*event));

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0) 
    NETLINK_CB(skb).pid = 0;        /* from kernel */
#else
    NETLINK_CB(skb).portid = 0;     /* from kernel */
#endif
    NETLINK_CB(skb).dst_group = 0;  /* unicast */
    netlink_unicast(band_steering_nl->bsteer_sock, skb, pid, MSG_DONTWAIT);
}

/**
 * @brief Handle a netlink message sent from user space.
 *
 * @param 2
 * @param 6
 * @param struct sk_buff *__skb  the buffer containing the data to receive
 * @param len  the length of the data to receive
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
static void ath_band_steering_netlink_receive(struct sk_buff *__skb)
#else
static void ath_band_steering_netlink_receive(struct sock *sk, int len)
#endif
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh = NULL;
    u_int8_t *data = NULL;
    u_int32_t pid;

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
    if ((skb = skb_get(__skb)) != NULL){
#else
    if ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
#endif
        /* process netlink message pointed by skb->data */
        nlh = (struct nlmsghdr *)skb->data;
        pid = nlh->nlmsg_pid;
        data = NLMSG_DATA(nlh);
        printk("Band steering events being sent to PID:%d\n", pid);
        band_steering_nl->bsteer_pid = pid;
        kfree_skb(skb);
    }
}
/**
  * @brief Initialize the netlink socket for the band steering module.
  *
  * @return  0 on success; -ENODEV on failure
  */
int ath_band_steering_netlink_init(void)
{

#if LINUX_VERSION_CODE >= KERNEL_VERSION (3,10,0)
    extern struct net init_net;
    struct netlink_kernel_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.groups = 1;
    cfg.input = &ath_band_steering_netlink_receive;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
    extern struct net init_net;

    struct netlink_kernel_cfg cfg = {
        .groups = 1,
        .input  = ath_band_steering_netlink_receive,
    };
#endif

    if (!band_steering_nl) {
        band_steering_nl = (struct band_steering_netlink *)
            kzalloc(sizeof(struct band_steering_netlink), GFP_KERNEL);
        if (!band_steering_nl) {
            return -ENODEV;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)/* >= (3,10,0) */
        band_steering_nl->bsteer_sock = (struct sock *)netlink_kernel_create(
                                                                              &init_net,
                                                                              NETLINK_BAND_STEERING_EVENT,
                                                                              &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
        band_steering_nl->bsteer_sock = (struct sock *)netlink_kernel_create(
                                                                              &init_net,
                                                                              NETLINK_BAND_STEERING_EVENT,
                                                                              THIS_MODULE, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,24)
        band_steering_nl->bsteer_sock = (struct sock *) netlink_kernel_create(
                                                                              &init_net,
                                                                              NETLINK_BAND_STEERING_EVENT, 1,
                                                                              &ath_band_steering_netlink_receive,
                                                                              NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,22)
        band_steering_nl->bsteer_sock = (struct sock *) netlink_kernel_create(
                                                                              NETLINK_BAND_STEERING_EVENT, 1,
                                                                              &ath_band_steering_netlink_receive,
                                                                              NULL, THIS_MODULE);

#else
        band_steering_nl->bsteer_sock = (struct sock *)netlink_kernel_create(
                                                                             NETLINK_BAND_STEERING_EVENT, 1,
                                                                             &ath_band_steering_netlink_receive,
                                                                             THIS_MODULE);
#endif
        if (!band_steering_nl->bsteer_sock) {
            kfree(band_steering_nl);
            band_steering_nl = NULL;
            printk("%s NETLINK_KERNEL_CREATE FAILED\n", __func__);
            return -ENODEV;
        }
        atomic_set(&band_steering_nl->bsteer_refcnt, 1);
        band_steering_nl->bsteer_pid = WLAN_DEFAULT_BSTEER_NETLINK_PID;
    } else {
        atomic_inc(&band_steering_nl->bsteer_refcnt);
    }
    return 0;
}
/**
  * @brief Close and destroy the netlink socket for the band steering module.
  *
  * @return 0 on success; non-zero on failure
  */
int ath_band_steering_netlink_delete(void)
{
    if (!band_steering_nl) {
        printk("%s band_steering_nl is NULL\n", __func__);
        return -ENODEV;
    }
    if (!atomic_dec_return(&band_steering_nl->bsteer_refcnt)) {
        if (band_steering_nl->bsteer_sock) {
            sock_release(band_steering_nl->bsteer_sock->sk_socket);
        }
        kfree(band_steering_nl);
        band_steering_nl = NULL;
    }
    return 0;
}
EXPORT_SYMBOL(ath_band_steering_netlink_send);
EXPORT_SYMBOL(ath_band_steering_netlink_init);
EXPORT_SYMBOL(ath_band_steering_netlink_delete);
#endif
