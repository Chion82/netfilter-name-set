#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

#include "resolv.h"
#include "local_ns_parser.h"

#define HASHTABLE_BUCKET_BITS (10)

#define DEFAULT_MAX_DNS_CACHE_LEN (10)

#define DNS_CACHE_MAX_CLEANUP (30)

#define MAX_SET_NAME_LENGTH (20)
#define NAME_SET_BUF_CAP (MAX_SET_NAME_LENGTH + 1)

#define DNS_RESULT_MAX_HOSTNAME_LEN (255)
#define DNS_RESULT_MAX_RR_LEN (10)

#define HASH_IP(ip) ((int)(ip))
#define HASH_IP6(ip) ((int)((ip)[0] + (ip)[1] + (ip)[2] + (ip)[3]))
#define IP_EQUAL(x, y) ((x) == (y))
#define IP6_EQUAL(x, y) ((x)[0] == (y)[0] && (x)[1] == (y)[1] && (x)[2] == (y)[2] && (x)[3] == (y)[3])
#define ASSIGN_IP6(dst, src) {(dst)[0]=(src)[0];(dst)[1]=(src)[1];(dst)[2]=(src)[2];(dst)[3]=(src)[3];}

struct xt_nameset_info {
  char set_name[NAME_SET_BUF_CAP];
  uint8_t flags;
};

struct dns_result {
  char hostname[DNS_RESULT_MAX_HOSTNAME_LEN];
  __be32 a_result[DNS_RESULT_MAX_RR_LEN];
  int a_result_len;
  __be32 aaaa_result[4][DNS_RESULT_MAX_RR_LEN];
  int aaaa_result_len;
};

struct dns_cache_item {
  char* hostname;
  union {
    __u32 all[4];
    __be32 ip;
    __be32 ip6[4];
    struct in_addr  in;
    struct in6_addr in6;
  } addr;
  char is_ip6;
  struct hlist_node hash_node;
  struct list_head list;
};


static int dns_cache_len = 0;

static int max_dns_cache_len __read_mostly = DEFAULT_MAX_DNS_CACHE_LEN;

static DEFINE_HASHTABLE(dns_cache_hash, HASHTABLE_BUCKET_BITS);
static LIST_HEAD(dns_cache_list);

static DEFINE_SPINLOCK(dns_cache_lock);

static void gc_worker(struct work_struct *work);
static struct workqueue_struct *wq __read_mostly;  
static DECLARE_DELAYED_WORK(gc_worker_wk, gc_worker);

static void
insert_dns_cache(struct dns_result* dr)
{
  char* hostname, *new_hostname;
  int hash, i, exists;
  struct dns_cache_item *item;
  __be32 ip;
  __be32 ip6[4];

  hostname = dr->hostname;
  for (i = 0; i < dr->a_result_len; i++) {
    ip = dr->a_result[i];
    hash = HASH_IP(ip);
    exists = 0;

    rcu_read_lock();
    hash_for_each_possible_rcu(dns_cache_hash, item, hash_node, hash) {
      if (item->is_ip6 == 0
        && IP_EQUAL(item->addr.ip, ip)
        && strcmp(item->hostname, hostname) == 0) {
        exists = 1;
        break;
      }
    }
    rcu_read_unlock();

    if (exists)
      continue;

    item = kmalloc(sizeof(struct dns_cache_item), GFP_ATOMIC);
    if (item == NULL){
      pr_debug("xt_nameset: insert_dns_cache(): insufficient memory\n");
      return;
    }
    item->is_ip6 = 0;
    item->addr.ip = ip;
    new_hostname = kmalloc(strlen(hostname) + 1, GFP_ATOMIC);
    if (item == NULL){
      kfree(item);
      pr_debug("xt_nameset: insert_dns_cache(): insufficient memory\n");
      return;
    }
    memset(new_hostname, 0x00, strlen(hostname) + 1);
    strcpy(new_hostname, hostname);

    item->hostname = new_hostname;

    spin_lock(&dns_cache_lock);

    hash_add_rcu(dns_cache_hash, &(item->hash_node), hash);
    list_add_rcu(&(item->list), &dns_cache_list);

    dns_cache_len++;

    spin_unlock(&dns_cache_lock);

    pr_debug("xt_nameset: add dns cache: %s - %pI4\n", item->hostname, &(item->addr.ip));

  }

  for (i = 0; i < dr->aaaa_result_len; i++) {
    ASSIGN_IP6(ip6, dr->aaaa_result[i]);
    hash = HASH_IP6(ip6);
    exists = 0;

    rcu_read_lock();
    hash_for_each_possible_rcu(dns_cache_hash, item, hash_node, hash) {
      if (item->is_ip6 == 1
        && IP6_EQUAL(item->addr.ip6, ip6)
        && strcmp(item->hostname, hostname) == 0) {
        exists = 1;
        break;
      }
    }
    rcu_read_unlock();

    if (exists)
      continue;

    item = kmalloc(sizeof(struct dns_cache_item), GFP_ATOMIC);
    if (item == NULL){
      pr_debug("xt_nameset: insert_dns_cache(): insufficient memory\n");
      return;
    }
    item->is_ip6 = 1;
    ASSIGN_IP6(item->addr.ip6, ip6);
    new_hostname = kmalloc(strlen(hostname) + 1, GFP_ATOMIC);
    if (item == NULL){
      kfree(item);
      pr_debug("xt_nameset: insert_dns_cache(): insufficient memory\n");
      return;
    }
    memset(new_hostname, 0x00, strlen(hostname) + 1);
    strcpy(new_hostname, hostname);

    item->hostname = new_hostname;

    spin_lock(&dns_cache_lock);

    hash_add_rcu(dns_cache_hash, &(item->hash_node), hash);
    list_add_rcu(&(item->list), &dns_cache_list);

    dns_cache_len++;

    spin_unlock(&dns_cache_lock);

    pr_debug("xt_nameset: add dns cache: %s - %pI6\n", item->hostname, &(item->addr.ip6));

  }
}

static int
remove_outdated_dns_cache(void)
{
  int remove_count, i;
  struct list_head *iter, *tmp;
  struct dns_cache_item *item;
  struct dns_cache_item *cache_to_remove[DNS_CACHE_MAX_CLEANUP];

  for (i = 0; i < DNS_CACHE_MAX_CLEANUP; i++) {
    cache_to_remove[i] = NULL;
  }

  spin_lock(&dns_cache_lock);

  remove_count = min(dns_cache_len - max_dns_cache_len, DNS_CACHE_MAX_CLEANUP);

  if (remove_count <= 0) {
    spin_unlock(&dns_cache_lock);
    return 0;
  }

  i = 0;
  list_for_each_prev_safe(iter, tmp, &dns_cache_list) {
    dns_cache_len--;

    item = list_entry(iter, struct dns_cache_item, list);

    list_del_rcu(&(item->list));
    hash_del_rcu(&(item->hash_node));
    cache_to_remove[i] = item;

    pr_debug("xt_nameset: del dns cache: %s\n", item->hostname);

    i++;
    if (i >= remove_count) {
      break;
    }
  }

  spin_unlock(&dns_cache_lock);

  synchronize_rcu();

  for (i = 0; i < remove_count; i++) {
    if (cache_to_remove[i] != NULL) {
      kfree((cache_to_remove[i])->hostname);
      kfree(cache_to_remove[i]);
    }
  }

  return remove_count;
}

static void
gc_worker(struct work_struct *work)
{
  remove_outdated_dns_cache();
  queue_delayed_work(wq, &gc_worker_wk, msecs_to_jiffies(500));
}

static int
parse_dns_response(const char* buf, const int length, struct dns_result* result)
{
  ns_msg msg;
  ns_rr rr_qd, rr_an;
  int rrnum, rrmax_qd, rrmax_an, tmp;
  char *hostname;
  u_int type;
  const u_char *rd;

  if (local_ns_initparse((const u_char *)buf, length, &msg) < 0) {
    return -1;
  }

  rrmax_qd = ns_msg_count(msg, ns_s_qd);
  if (rrmax_qd == 0) {
    return -2;
  }
  rrmax_an = ns_msg_count(msg, ns_s_an);
  if (rrmax_an == 0) {
    return -3;
  }

  for (rrnum = 0; rrnum < rrmax_qd; rrnum++) {
    if (local_ns_parserr(&msg, ns_s_qd, rrnum, &rr_qd)) {
      return -1;
    }
    hostname = ns_rr_name(rr_qd);
  }

  memset(result->hostname, 0x00, DNS_RESULT_MAX_HOSTNAME_LEN);
  strncpy(result->hostname, hostname, DNS_RESULT_MAX_HOSTNAME_LEN - 1);
  result->a_result_len = 0;
  result->aaaa_result_len = 0;

  for (rrnum = 0; rrnum < rrmax_an; rrnum++) {
    if (local_ns_parserr(&msg, ns_s_an, rrnum, &rr_an)) {
      return -1;
    }
    type = ns_rr_type(rr_an);
    rd = ns_rr_rdata(rr_an);

    if (type == ns_t_a && rd != NULL) {
      result->a_result[result->a_result_len] = *((__be32*)rd);
      result->a_result_len ++;
    }

    if (type == ns_t_aaaa && rd != NULL) {
      for (tmp = 0; tmp < 4; tmp++) {
        result->aaaa_result[result->aaaa_result_len][tmp] = *((__be32*)rd + tmp);
      }
      result->aaaa_result_len ++;
    }
  }

  return 0;
}

// static bool
// nameset_match4(const struct sk_buff *skb, struct xt_action_param *par)
// {

// }

// static bool
// nameset_match6(const struct sk_buff *skb, struct xt_action_param *par)
// {

// }

// static int
// nameset_match4_checkentry(const struct xt_mtchk_param *par)
// {

// }

// static int
// nameset_match6_checkentry(const struct xt_mtchk_param *par)
// {

// }

// static void
// nameset_match4_destroy(const struct xt_mtdtor_param *par)
// {

// }

// static void
// nameset_match6_destroy(const struct xt_mtdtor_param *par)
// {

// }

static int
nameset_target4_checkentry(const struct xt_tgchk_param *par)
{
  return 0;
}

static void nameset_target4_destroy(const struct xt_tgdtor_param *par)
{

}

static unsigned int
nameset_target4(struct sk_buff *skb, const struct xt_action_param *par)
{
  struct iphdr *iph;
  struct udphdr *udph;
  int udp_payload_len;
  char* udp_payload;
  struct dns_result dr;
  unsigned int ret;

  ret = XT_CONTINUE;

  if (skb_network_header_len(skb) < sizeof(struct iphdr) ||
    skb_transport_offset(skb) <= 0) {
    return ret;
  }

  iph = ip_hdr(skb);
  if (iph == NULL) {
    return ret;
  }

  if (iph->protocol != IPPROTO_UDP) {
    return ret;
  }

  udp_payload_len = skb->len - skb_transport_offset(skb) - sizeof(struct udphdr);

  if (udp_payload_len <= 0) {
    return ret;
  }

  udph = (struct udphdr*)skb_transport_header(skb);
  if (udph == NULL) {
    return ret;
  }

  if (be16_to_cpu(udph->len) != sizeof(struct udphdr) + udp_payload_len) {
    pr_debug("xt_nameset: invalid length in udp header.\n");
    return ret;
  }

  udp_payload = (char*)udph + sizeof(struct udphdr);

  if (parse_dns_response(udp_payload, udp_payload_len, &dr) != 0) {
    return ret;
  }
  insert_dns_cache(&dr);

  return ret;
}

static struct xt_target nameset_targets[] __read_mostly = {
 {
  .name       = "NAMESET",
  .family     = NFPROTO_IPV4,
  .revision   = 0,
  .target     = nameset_target4,
  .targetsize = sizeof(struct xt_nameset_info),
  .checkentry = nameset_target4_checkentry,
  .destroy    = nameset_target4_destroy,
  .me         = THIS_MODULE,
 },
};

static int __init nameset_init(void)
{
  wq = create_singlethread_workqueue("xt_nameset");
  if (wq == NULL) {
    printk(KERN_ERR "xt_nameset: create_singlethread_workqueue() failed. xt_nameset not registered.\n");
    return 0;
  }
  queue_delayed_work(wq, &gc_worker_wk, msecs_to_jiffies(500));
  pr_debug("xt_nameset: nameset_init\n");

  return xt_register_targets(nameset_targets, ARRAY_SIZE(nameset_targets));
}

static void nameset_exit(void)
{
  xt_unregister_targets(nameset_targets, ARRAY_SIZE(nameset_targets));

  cancel_delayed_work_sync(&gc_worker_wk);
  if (wq) {
    flush_workqueue(wq);
    destroy_workqueue(wq);
  }
}

module_init(nameset_init);
module_exit(nameset_exit);

MODULE_LICENSE("GPL");

