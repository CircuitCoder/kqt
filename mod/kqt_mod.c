#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/quic.h>

#include <net/rtnetlink.h>
#include <net/handshake.h>
#include <net/sock.h>

static const char KQT_ALPN[] = "kqt/0.1";
static const int KQT_ALPN_LEN = sizeof(KQT_ALPN) - 1;

enum kqt_peer_state {
  KQT_PEER_CONNECTING,
  KQT_PEER_ESTABLISHED,
  KQT_PEER_REMOVED,
};

struct kqt_peer {
  struct socket *sock;
  enum kqt_peer_state state;
  struct list_head list;
};

struct kqt_peer_handshake_handle {
  struct completion done;
  int status;
};

void kqt_peer_handshake_callback(void *data, int status, key_serial_t peerid) {
  struct kqt_peer_handshake_handle *handle = data;
  handle->status = status;
  complete_all(&handle->done);
}

int kqt_peer_handshake(struct socket *sock) {
  struct kqt_peer_handshake_handle handshake_done;
  int err;

  init_completion(&handshake_done.done);

  // FIXME: cert chain
  // TODO: timeut
  struct tls_handshake_args handshake_args = {
    .ta_sock = sock,
    .ta_done = kqt_peer_handshake_callback,
    .ta_data = &handshake_done,
  };
  err = tls_client_hello_x509(&handshake_args, GFP_KERNEL);
  if (err) return err;

  // TODO: timeut
  err = wait_for_completion_interruptible(&handshake_done.done);

  if (err <= 0) {
    tls_handshake_cancel(sock->sk);
    return -ETIMEDOUT;
  }
  return handshake_done.status;
}

int kqt_peer_open(struct kqt_peer *peer, struct sockaddr_in remote) {
  struct socket *sock;
  int err;

  err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
  if (err) return err;

  err = quic_kernel_setsockopt(sock->sk, QUIC_SOCKOPT_ALPN, (char *) KQT_ALPN, KQT_ALPN_LEN);
  if (err) goto free_sock;

  err = kernel_connect(sock,(struct sockaddr *)&remote, sizeof(remote), 0);
  if (err) goto free_sock;

  peer->state = KQT_PEER_CONNECTING;

  rtnl_unlock();
  err = kqt_peer_handshake(sock);
  rtnl_lock();
  if (err) goto free_sock;

  if (peer->state == KQT_PEER_REMOVED) {
    err = -ECONNABORTED;
    goto free_sock;
  }
  peer->sock = sock;
  wmb();
  peer->state = KQT_PEER_ESTABLISHED;
  return 0;

free_sock:
  sock_release(sock);
  return err;
}

struct kqt_device {
  struct list_head peers;
};

static int kqt_peer_send(struct kqt_peer *peer, struct sk_buff *skb) {
  struct msghdr msg = {0};
  struct kvec iov;
  int err;

  if (!peer->sock) {
    pr_err("kqt: peer socket is NULL\n");
    return -EINVAL;
  }

  iov.iov_base = skb->data;
  iov.iov_len = skb->len;
  msg.msg_flags = MSG_DATAGRAM;

  return kernel_sendmsg(peer->sock, &msg, &iov, 1, skb->len);
}

netdev_tx_t kqt_netdev_xmit(struct sk_buff *skb, struct net_device *dev) {
  struct ethhdr *eth = eth_hdr(skb);
  struct kqt_device *kqt_dev = netdev_priv(dev);
  struct kqt_peer *peer;
  int err;

  // Broadcast for now
  rcu_read_lock_bh();
  list_for_each_entry_rcu(peer, &kqt_dev->peers, list) {
    if (peer->state != KQT_PEER_ESTABLISHED) continue;
    err = kqt_peer_send(peer, skb);
    if (err) {
      pr_err("kqt: failed to send skb to peer: %d\n", err);
    }
  }
  rcu_read_unlock_bh();
  return NETDEV_TX_OK;
}
static const struct net_device_ops kqt_netdev_ops = {
  .ndo_start_xmit = kqt_netdev_xmit,
};

static const struct device_type device_type = { .name = "kqt" };

static void kqt_netdev_setup(struct net_device *dev) {
  dev->netdev_ops = &kqt_netdev_ops;
  ether_setup(dev);
  eth_hw_addr_random(dev);
  dev->priv_flags |= IFF_NO_QUEUE;
  SET_NETDEV_DEVTYPE(dev, &device_type);
  dev->max_mtu = ETH_DATA_LEN - 40; // TODO: more detailed computation
  dev->mtu = dev->max_mtu;

  pr_info("kqt: netdev setup\n");
}

static void kqt_netdev_destruct(struct net_device *dev) {
  pr_info("kqt: netdev destruct\n");
  free_netdev(dev);
}

static int kqt_netdev_newlink(struct net *src_net, struct net_device *dev,
                               struct nlattr *tb[], struct nlattr *data[],
                               struct netlink_ext_ack *extack) {
  int ret;
  struct kqt_device *kqt_dev;

  kqt_dev = netdev_priv(dev);
  INIT_LIST_HEAD(&kqt_dev->peers);
  dev->priv_destructor = kqt_netdev_destruct;
  ret = register_netdevice(dev);
  if (ret)
    return ret;
  pr_info("kqt: netdev newlink, needs_free_netdev = %d\n", dev->needs_free_netdev);
  return 0;
}

static struct rtnl_link_ops kqt_link_ops = {
  .kind = "kqt",
  .priv_size = sizeof(struct kqt_device),
  .setup = kqt_netdev_setup,
  .newlink = kqt_netdev_newlink,
};

static int __init kqt_module_init(void) {
  int ret;

  ret = rtnl_link_register(&kqt_link_ops);
  if (ret) return ret;

  pr_info("kqt: init\n");
  return 0;
}

static void __exit kqt_module_exit(void) {
  rtnl_link_unregister(&kqt_link_ops);
  pr_info("kqt: exit\n");
}

module_init(kqt_module_init);
module_exit(kqt_module_exit);

MODULE_LICENSE("GPL");
