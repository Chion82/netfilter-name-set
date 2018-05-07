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
#include <linux/stringhash.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

#include "resolv.h"
#include "local_ns_parser.h"

#define HASHTABLE_BUCKET_BITS (10)

#ifdef FLOOD_DEV_TEST

#define DEFAULT_MAX_DNS_CACHE_LEN (4)
#define DEFAULT_MAX_MATCH_RESULT_CACHE_LEN (4)
#define GC_WORKER_INTERVAL (1)

#else

#define DEFAULT_MAX_DNS_CACHE_LEN (16384)
#define DEFAULT_MAX_MATCH_RESULT_CACHE_LEN (16384)
#define GC_WORKER_INTERVAL (2000)

#endif

#define MAX_SET_NAME_LENGTH (20)
#define NAME_SET_BUF_CAP (MAX_SET_NAME_LENGTH + 1)

#define DNS_RESULT_MAX_HOSTNAME_LEN (255)
#define DNS_RESULT_MAX_RR_LEN (10)

#define USER_BUF_LEN (512)

#define HASH_IP(ip) ((int)(ip))
#define HASH_IP6(ip) ((int)((ip)[0] + (ip)[1] + (ip)[2] + (ip)[3]))
#define IP_EQUAL(x, y) ((x) == (y))
#define IP6_EQUAL(x, y) ((x)[0] == (y)[0] && (x)[1] == (y)[1] && (x)[2] == (y)[2] && (x)[3] == (y)[3])
#define ASSIGN_IP6(dst, src) {(dst)[0]=(src)[0];(dst)[1]=(src)[1];(dst)[2]=(src)[2];(dst)[3]=(src)[3];}

struct xt_nameset_info {
  char set_name[NAME_SET_BUF_CAP];
  uint8_t flags;
};

enum {
  XT_NAMESET_HOOK_DNS_RESPONSE = 1 << 0,
  XT_NAMESET_SRC = 1 << 1,
  XT_NAMESET_DST = 1 << 2,
  XT_NAMESET_MATCH_INVERT = 1 << 3,
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

struct nameset_record {
  char* hostname;
  char* setname;
  struct hlist_node hash_node;
};

struct set_match {
  char* setname;
  struct list_head list;
};

struct match_result {
  union {
    __u32 all[4];
    __be32 ip;
    __be32 ip6[4];
    struct in_addr  in;
    struct in6_addr in6;
  } addr;
  char is_ip6;
  struct list_head match_sets;

  struct hlist_node hash_node;
  struct list_head list;
};

static int dns_cache_len = 0;
static int max_dns_cache_len __read_mostly = DEFAULT_MAX_DNS_CACHE_LEN;
static DEFINE_HASHTABLE(dns_cache_hash, HASHTABLE_BUCKET_BITS);
static LIST_HEAD(dns_cache_list);
static DEFINE_SPINLOCK(dns_cache_lock);

static const char* salt = "nameset";
static DEFINE_HASHTABLE(nameset_record_hash, HASHTABLE_BUCKET_BITS);
static DEFINE_SPINLOCK(nameset_record_lock);

static int match_result_cache_len = 0;
static int max_match_result_cache_len __read_mostly = DEFAULT_MAX_MATCH_RESULT_CACHE_LEN;
static DEFINE_HASHTABLE(match_result_cache_hash, HASHTABLE_BUCKET_BITS);
static LIST_HEAD(match_result_cache_list);
static DEFINE_SPINLOCK(match_result_cache_lock);

static void gc_worker(struct work_struct *work);
static struct workqueue_struct *wq __read_mostly;  
static DECLARE_DELAYED_WORK(gc_worker_wk, gc_worker);

static DEFINE_MUTEX(user_command_lock);
static char user_response_buf[USER_BUF_LEN];
static ssize_t user_response_len;
static int user_response_ready_read;

static int remove_all_match_result_cache __read_mostly = 0;

static atomic_t cleanup;

static struct nameset_record init_records[] = {

};

static int
fnmatch(char str[], char pattern[], int n, int m) 
{
  int lookup[n + 1][m + 1];
  int i, j;

  if (m == 0)
      return (n == 0);

  memset(lookup, 0, sizeof(lookup));

  lookup[0][0] = 1;

  for (j = 1; j <= m; j++)
    if (pattern[j - 1] == '*')
      lookup[0][j] = lookup[0][j - 1];

  for (i = 1; i <= n; i++) {
    for (j = 1; j <= m; j++) {
        
      if (pattern[j - 1] == '*')
        lookup[i][j] = lookup[i][j - 1] ||
                       lookup[i - 1][j];
    
      else if (pattern[j - 1] == '?' ||
        str[i - 1] == pattern[j - 1])
        lookup[i][j] = lookup[i - 1][j - 1];

      else lookup[i][j] = 0;
    }
  }

  return lookup[n][m];
}

/* should only be called after synchronize_rcu() */
static void
kill_match_result(struct match_result *result)
{
  struct list_head *iter, *tmp;
  struct set_match *match;
  
  if (result == NULL) {
    return;
  }

  list_for_each_safe(iter, tmp, &(result->match_sets)) {
    match = list_entry(iter, struct set_match, list);
    list_del(&(match->list));

    kfree(match->setname);
    kfree(match);
  }

  kfree(result);
}

static int
insert_nameset_record(const char* setname, const char* hostname)
{
  struct nameset_record *record;
  uint hash;

  hash = full_name_hash(salt, hostname, strlen(hostname));

  rcu_read_lock();

  hash_for_each_possible_rcu(nameset_record_hash, record, hash_node, hash) {
    if (strcmp(record->setname, setname) == 0
      && strcmp(record->hostname, hostname) == 0) {
      rcu_read_unlock();
      return -EEXIST;
    }
  }

  record = kmalloc(sizeof(struct nameset_record), GFP_ATOMIC);
  if (record == NULL) {
    pr_debug("xt_nameset: insert_nameset_record(): insufficient memory\n");
    rcu_read_unlock();
    return -ENOMEM;
  }
  record->hostname = kmalloc(strlen(hostname) + 1, GFP_ATOMIC);
  if (record->hostname == NULL) {
    pr_debug("xt_nameset: insert_nameset_record(): insufficient memory\n");
    kfree(record);
    rcu_read_unlock();
    return -ENOMEM;
  }
  memset(record->hostname, 0x00, strlen(hostname) + 1);
  strcpy(record->hostname, hostname);

  record->setname = kmalloc(strlen(setname) + 1, GFP_ATOMIC);
  if (record->setname == NULL) {
    pr_debug("xt_nameset: insert_nameset_record(): insufficient memory\n");
    kfree(record->hostname);
    kfree(record);
    rcu_read_unlock();
    return -ENOMEM;
  }
  memset(record->setname, 0x00, strlen(setname) + 1);
  strcpy(record->setname, setname);

  spin_lock_bh(&nameset_record_lock);
  hash_add_rcu(nameset_record_hash, &(record->hash_node), hash);

  spin_unlock_bh(&nameset_record_lock);

  rcu_read_unlock();

  pr_debug("xt_nameset: record inserted: %s %s\n", setname, hostname);

  return 0;
}

static int
find_and_kill_nameset_record(const char* setname, const char* hostname)
{
  int ret;
  uint hash;
  struct nameset_record *record_to_remove, *record;
  struct hlist_node *tmp;

  ret = 0;
  hash = full_name_hash(salt, hostname, strlen(hostname));
  record_to_remove = NULL;

  spin_lock_bh(&nameset_record_lock);

  hash_for_each_possible_safe(nameset_record_hash, record, tmp, hash_node, hash) {
    if (strcmp(record->setname, setname) == 0
      && strcmp(record->hostname, hostname) == 0) {
      record_to_remove = record;

      hash_del_rcu(&(record_to_remove->hash_node));

      break;
    }
  }

  spin_unlock_bh(&nameset_record_lock);

  synchronize_rcu();

  if (record_to_remove != NULL) {
    kfree(record_to_remove->setname);
    kfree(record_to_remove->hostname);
    kfree(record_to_remove);

    pr_debug("xt_nameset: record deleted: %s %s\n", setname, hostname);

    return 0;
  }

  return -ENOENT;
}

static void
init_nameset_records(void)
{
  struct nameset_record *init_record;
  int i;
  for (i = 0; i < ARRAY_SIZE(init_records); i++) {
    init_record = init_records + i;
    insert_nameset_record(init_record->setname, init_record->hostname);
  }
}


/* should be call within rcu_read_lock() critical section */
static struct match_result*
get_match_result(__be32* addr, const int is_ip6)
{
  int ip_hash, tmp;
  struct match_result *cache_result, *result;
  struct nameset_record *record;
  struct dns_cache_item *dns_cache;
  struct set_match *match;
  char *hostname, *match_setname;

  __be32 ip = 0, *ip6 = NULL;

  if (is_ip6) {
    ip6 = addr;
    ip_hash = HASH_IP6(ip6);
  } else {
    ip = *addr;
    ip_hash = HASH_IP(ip);
  }

  hash_for_each_possible_rcu(match_result_cache_hash, cache_result, hash_node, ip_hash) {
    if (is_ip6 && cache_result->is_ip6 == is_ip6
      && IP6_EQUAL(cache_result->addr.ip6, ip6)) {
      
      pr_debug("xt_nameset: hit match cache result\n");

      return cache_result;
    }
    if (!is_ip6 && cache_result->is_ip6 == is_ip6
      && IP_EQUAL(cache_result->addr.ip, ip)) {

      pr_debug("xt_nameset: hit match cache result\n");

      return cache_result;
    }
  }

  result = kmalloc(sizeof(struct match_result), GFP_ATOMIC);
  if (result == NULL) {
    return NULL;
  }

  if (is_ip6) {
    ASSIGN_IP6(result->addr.ip6, ip6);
  } else {
    result->addr.ip = ip;
  }
  result->is_ip6 = is_ip6;

  INIT_LIST_HEAD(&(result->match_sets));

  hash_for_each_possible_rcu(dns_cache_hash, dns_cache, hash_node, ip_hash) {
    if (dns_cache->is_ip6 == is_ip6 &&
      ( (!is_ip6 && IP_EQUAL(ip, dns_cache->addr.ip))
      || (is_ip6 && IP6_EQUAL(ip6, dns_cache->addr.ip6)) ) ) {

      hostname = dns_cache->hostname;

      hash_for_each_rcu(nameset_record_hash, tmp, record, hash_node) {
        if (fnmatch(hostname, record->hostname, strlen(hostname), strlen(record->hostname))) {
          match = kmalloc(sizeof(struct set_match), GFP_ATOMIC);
          if (match == NULL) {
            kill_match_result(result);
            return NULL;
          }
          match_setname = kmalloc(strlen(record->setname) + 1, GFP_ATOMIC);
          if (match_setname == NULL) {
            kfree(match);
            kill_match_result(result);
            return NULL;
          }
          memset(match_setname, 0x00, strlen(record->setname) + 1);
          strcpy(match_setname, record->setname);
          match->setname = match_setname;

          list_add(&(match->list), &(result->match_sets));
        }
      }
    }
  }

  if (list_empty(&(result->match_sets))) {
    kill_match_result(result);
    return NULL;
  }

  spin_lock_bh(&match_result_cache_lock);

  hash_add_rcu(match_result_cache_hash, &(result->hash_node), ip_hash);
  list_add_rcu(&(result->list), &match_result_cache_list);
  match_result_cache_len++;

  pr_debug("xt_nameset: created new match result cache \n");

  spin_unlock_bh(&match_result_cache_lock);

  return result;
}

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

    if (exists) {
      rcu_read_unlock();
      continue;
    }

    item = kmalloc(sizeof(struct dns_cache_item), GFP_ATOMIC);
    if (item == NULL){
      pr_debug("xt_nameset: insert_dns_cache(): insufficient memory\n");
      rcu_read_unlock();
      return;
    }
    item->is_ip6 = 0;
    item->addr.ip = ip;
    new_hostname = kmalloc(strlen(hostname) + 1, GFP_ATOMIC);
    if (item == NULL){
      kfree(item);
      pr_debug("xt_nameset: insert_dns_cache(): insufficient memory\n");
      rcu_read_unlock();
      return;
    }
    memset(new_hostname, 0x00, strlen(hostname) + 1);
    strcpy(new_hostname, hostname);

    item->hostname = new_hostname;

    spin_lock_bh(&dns_cache_lock);

    hash_add_rcu(dns_cache_hash, &(item->hash_node), hash);
    list_add_rcu(&(item->list), &dns_cache_list);

    dns_cache_len++;

    spin_unlock_bh(&dns_cache_lock);

    pr_debug("xt_nameset: add dns cache: %s - %pI4\n", item->hostname, &(item->addr.ip));

    rcu_read_unlock();
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

    if (exists) {
      rcu_read_unlock();
      continue;
    }

    item = kmalloc(sizeof(struct dns_cache_item), GFP_ATOMIC);
    if (item == NULL){
      pr_debug("xt_nameset: insert_dns_cache(): insufficient memory\n");
      rcu_read_unlock();
      return;
    }
    item->is_ip6 = 1;
    ASSIGN_IP6(item->addr.ip6, ip6);
    new_hostname = kmalloc(strlen(hostname) + 1, GFP_ATOMIC);
    if (item == NULL){
      kfree(item);
      pr_debug("xt_nameset: insert_dns_cache(): insufficient memory\n");
      rcu_read_unlock();
      return;
    }
    memset(new_hostname, 0x00, strlen(hostname) + 1);
    strcpy(new_hostname, hostname);

    item->hostname = new_hostname;

    spin_lock_bh(&dns_cache_lock);

    hash_add_rcu(dns_cache_hash, &(item->hash_node), hash);
    list_add_rcu(&(item->list), &dns_cache_list);

    dns_cache_len++;

    spin_unlock_bh(&dns_cache_lock);

    pr_debug("xt_nameset: add dns cache: %s - %pI6\n", item->hostname, &(item->addr.ip6));

    rcu_read_unlock();
  }
}

static int
remove_outdated_match_result_cache(const int remove_all)
{
  int remove_count;
  struct match_result *item_to_remove;

  remove_count = 0;

delete_one:
  
  spin_lock_bh(&match_result_cache_lock);

  item_to_remove = NULL;

  if ((match_result_cache_len > max_match_result_cache_len || remove_all)
    && !(list_empty(&match_result_cache_list))) {
    item_to_remove = list_last_entry(&match_result_cache_list, struct match_result, list);

    list_del_rcu(&(item_to_remove->list));
    hash_del_rcu(&(item_to_remove->hash_node));

    if (item_to_remove->is_ip6) {
      pr_debug("xt_nameset: del match result cache: %pI6\n", item_to_remove->addr.ip6);
    } else {
      pr_debug("xt_nameset: del match result cache: %pI4\n", &(item_to_remove->addr.ip));
    }
    match_result_cache_len--;
    remove_count++;
  }

  spin_unlock_bh(&match_result_cache_lock);

  synchronize_rcu();

  if (item_to_remove != NULL) {
    kill_match_result(item_to_remove);
    goto delete_one;
  }

  return remove_count;
}

static int
remove_outdated_dns_cache(const int remove_all)
{
  int remove_count;
  struct dns_cache_item *item_to_remove;

  remove_count = 0;

delete_one:

  spin_lock_bh(&dns_cache_lock);

  item_to_remove = NULL;

  if ((dns_cache_len > max_dns_cache_len || remove_all)
    && !(list_empty(&dns_cache_list))) {
    item_to_remove = list_last_entry(&dns_cache_list, struct dns_cache_item, list);

    list_del_rcu(&(item_to_remove->list));
    hash_del_rcu(&(item_to_remove->hash_node));

    dns_cache_len--;
    remove_count++;

    pr_debug("xt_nameset: del dns cache: %s\n", item_to_remove->hostname);
  }

  spin_unlock_bh(&dns_cache_lock);

  synchronize_rcu();

  if (item_to_remove != NULL) {
    kfree(item_to_remove->hostname);
    kfree(item_to_remove);
    goto delete_one;
  }

  return remove_count;
}

static void
gc_worker(struct work_struct *work)
{
  remove_outdated_dns_cache(0);
  remove_outdated_match_result_cache(remove_all_match_result_cache);

  remove_all_match_result_cache = 0;

  if (atomic_read(&cleanup) == 0)
    queue_delayed_work(wq, &gc_worker_wk, msecs_to_jiffies(GC_WORKER_INTERVAL));
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
    return -EINVAL;
  }

  rrmax_qd = ns_msg_count(msg, ns_s_qd);
  if (rrmax_qd == 0) {
    return -EINVAL;
  }
  rrmax_an = ns_msg_count(msg, ns_s_an);
  if (rrmax_an == 0) {
    return -EINVAL;
  }

  for (rrnum = 0; rrnum < rrmax_qd; rrnum++) {
    if (local_ns_parserr(&msg, ns_s_qd, rrnum, &rr_qd)) {
      return -EINVAL;
    }
    hostname = ns_rr_name(rr_qd);
  }

  memset(result->hostname, 0x00, DNS_RESULT_MAX_HOSTNAME_LEN);
  strncpy(result->hostname, hostname, DNS_RESULT_MAX_HOSTNAME_LEN - 1);
  result->a_result_len = 0;
  result->aaaa_result_len = 0;

  for (rrnum = 0; rrnum < rrmax_an; rrnum++) {
    if (local_ns_parserr(&msg, ns_s_an, rrnum, &rr_an)) {
      return -EINVAL;
    }
    type = ns_rr_type(rr_an);
    rd = ns_rr_rdata(rr_an);

    if (type == ns_t_a && rd != NULL
      && result->a_result_len < DNS_RESULT_MAX_RR_LEN) {
      result->a_result[result->a_result_len] = *((__be32*)rd);
      result->a_result_len ++;
    }

    if (type == ns_t_aaaa && rd != NULL
      && result->aaaa_result_len < DNS_RESULT_MAX_RR_LEN) {
      for (tmp = 0; tmp < 4; tmp++) {
        result->aaaa_result[result->aaaa_result_len][tmp] = *((__be32*)rd + tmp);
      }
      result->aaaa_result_len ++;
    }
  }

  return 0;
}

static int
nameset_target4_checkentry(const struct xt_tgchk_param *par)
{
  return 0;
}

static void
nameset_target4_destroy(const struct xt_tgdtor_param *par)
{

}

static bool
nameset_match4(const struct sk_buff *skb, struct xt_action_param *par)
{
  const struct xt_nameset_info *info;
  const char* setname;
  struct iphdr *iph;
  struct match_result *mr;

  struct set_match *match;

  int matched, invert;

  __be32 ip;

  info = par->matchinfo;

  matched = 0;
  invert = 0;

  if (info->flags & XT_NAMESET_MATCH_INVERT) {
    invert = 1;
  }

  if (skb_network_header_len(skb) < sizeof(struct iphdr)) {
    goto out;
  }

  iph = ip_hdr(skb);
  if (iph == NULL) {
    goto out;
  }

  if (info->flags & XT_NAMESET_DST) {
    ip = iph->daddr;
  } else {
    ip = iph->saddr;
  }

  setname = info->set_name;

  rcu_read_lock();

  mr = get_match_result(&ip, 0);

  if (mr == NULL) {
    rcu_read_unlock();
    goto out;
  }

  list_for_each_entry(match, &(mr->match_sets), list) {
    if (strcmp(setname, match->setname) == 0) {
      matched = 1;
      pr_debug("xt_nameset: nameset_match4(): %pI4 matches %s\n", &ip, setname);
      break;
    }
  }

  rcu_read_unlock();

out:
  if (invert)
    return !matched;
  else
    return matched;
}

// static bool
// nameset_match6(const struct sk_buff *skb, struct xt_action_param *par)
// {

// }

static int
nameset_match4_checkentry(const struct xt_mtchk_param *par)
{
  return 0;
}

// static int
// nameset_match6_checkentry(const struct xt_mtchk_param *par)
// {

// }

static void
nameset_match4_destroy(const struct xt_mtdtor_param *par)
{

}

// static void
// nameset_match6_destroy(const struct xt_mtdtor_param *par)
// {

// }

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

/* non-threadsafe. only for module cleanup. */
static void
destroy_all_dns_cache(void)
{
  struct list_head *iter, *tmp;
  struct dns_cache_item *item;

  list_for_each_safe(iter, tmp, &dns_cache_list) {
   
    item = list_entry(iter, struct dns_cache_item, list);
    list_del(&(item->list));
    hash_del(&(item->hash_node));

    kfree(item->hostname);
    kfree(item);
  }

  dns_cache_len = 0;
}

/* non-threadsafe. only for module cleanup. */
static void
destroy_all_nameset_records(void)
{
  struct nameset_record* record;
  struct hlist_node *tmp;
  int i;

  hash_for_each_safe(nameset_record_hash, i, tmp, record, hash_node) {
    hash_del(&(record->hash_node));

    kfree(record->hostname);
    kfree(record->setname);
    kfree(record);
  }
}

/* non-threadsafe. only for module cleanup. */
static void
destroy_all_match_result_cache(void)
{
  struct match_result* result;
  struct list_head *iter, *tmp;

  list_for_each_safe(iter, tmp, &match_result_cache_list) {
    result = list_entry(iter, struct match_result, list);

    list_del(&(result->list));
    hash_del(&(result->hash_node));

    kill_match_result(result);
  }

  match_result_cache_len = 0;
}

static inline int
set_user_response(const char *message)
{
  memset(user_response_buf, 0x00, USER_BUF_LEN);
  strcpy(user_response_buf, message);
  user_response_len = strlen(message) + 1;
  return user_response_len;
}

static int
execute_user_command(char* raw_command)
{
  int arg_count, ret;
  char arg0[20], arg1[30], arg2[255], arg3[50];
  memset(arg0, 0x00, 20);
  memset(arg1, 0x00, 30);
  memset(arg2, 0x00, 255);
  memset(arg3, 0x00, 50);

  arg_count = sscanf(raw_command, "%19s %29s %254s %49s", arg0, arg1, arg2, arg3);

  if (arg_count < 1) {
    goto invalid_command;
  }

  if (strcmp(arg0, "add") == 0) {
    if (arg_count != 3) {
      goto invalid_argument;
    }
    if (strlen(arg1) < 1 || strlen(arg1) > MAX_SET_NAME_LENGTH) {
      goto invalid_argument;
    }
    if (strlen(arg2) < 1 || strlen(arg2) > 254) {
      goto invalid_argument;
    }

    ret = insert_nameset_record(arg1, arg2);

    switch (ret) {
      case -EINVAL:
        goto invalid_argument;
        break;
      case -EEXIST:
        set_user_response("record already exists.\n");
        return ret;
      case 0:
        set_user_response("record inserted.\n");
        remove_all_match_result_cache = 1;
        return ret;
      default:
        set_user_response("failed to insert record.\n");
        return ret;
    }
  }

  if (strcmp(arg0, "del") == 0) {
    if (arg_count != 3) {
      goto invalid_argument;
    }
    if (strlen(arg1) < 1 || strlen(arg1) > MAX_SET_NAME_LENGTH) {
      goto invalid_argument;
    }
    if (strlen(arg2) < 1 || strlen(arg2) > 254) {
      goto invalid_argument;
    }

    ret = find_and_kill_nameset_record(arg1, arg2);

    switch (ret) {
      case -EINVAL:
        goto invalid_argument;
        break;
      case -ENOENT:
        set_user_response("record not found.\n");
        return ret;
      case 0:
        set_user_response("record deleted.\n");
        remove_all_match_result_cache = 1;
        return ret;
      default:
        set_user_response("failed to delete record.\n");
        return ret;
    }
  }

invalid_command:
  set_user_response("invalid command.\n");
  return -EINVAL;

invalid_argument:
  set_user_response("invalid arguments.\n");
  return -EINVAL;
}

static int
user_open_proc(struct inode *node, struct file *file)
{
  mutex_lock(&user_command_lock);

  user_response_ready_read = 1;

  mutex_unlock(&user_command_lock);

  return 0;
}

static ssize_t
user_read_proc(struct file *p_file, char *buf, size_t count, loff_t *p_off)
{
  mutex_lock(&user_command_lock);

  count = user_response_len < count ? user_response_len : count;

  if (!user_response_ready_read) {
    mutex_unlock(&user_command_lock);
    return 0;
  }

  copy_to_user(buf, user_response_buf, count);

  user_response_ready_read = 0;

  mutex_unlock(&user_command_lock);

  return count;
}

static ssize_t
user_write_proc(struct file *p_file, const char *buf, size_t count, loff_t *p_off)
{
  char user_command_buf[USER_BUF_LEN];
  memset(user_command_buf, 0x00, USER_BUF_LEN);

  count = USER_BUF_LEN < count ? USER_BUF_LEN : count;

  mutex_lock(&user_command_lock);

  copy_from_user(user_command_buf, buf, count);
  execute_user_command(user_command_buf);

  mutex_unlock(&user_command_lock);

  return count;
}

struct file_operations proc_fops = {
  read: user_read_proc,
  write: user_write_proc,
  open: user_open_proc,
};

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

static struct xt_match nameset_matches[] __read_mostly = {
  {
    .name       = "nameset",
    .family     = NFPROTO_IPV4,
    .revision   = 0,
    .match      = nameset_match4,
    .matchsize  = sizeof(struct xt_nameset_info),
    .checkentry = nameset_match4_checkentry,
    .destroy    = nameset_match4_destroy,
    .me         = THIS_MODULE,
  },
};

static int __init nameset_init(void)
{
  atomic_set(&cleanup, 0);

  init_nameset_records();

  wq = create_singlethread_workqueue("xt_nameset");
  if (wq == NULL) {
    printk(KERN_ERR "xt_nameset: create_singlethread_workqueue() failed. xt_nameset not registered.\n");
    return 0;
  }
  queue_delayed_work(wq, &gc_worker_wk, msecs_to_jiffies(GC_WORKER_INTERVAL));
  pr_debug("xt_nameset: nameset_init\n");

  memset(user_response_buf, 0x00, USER_BUF_LEN);
  user_response_len = 0;
  user_response_ready_read = 0;
  proc_create("nameset_command", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP, init_net.proc_net, &proc_fops);

  xt_register_matches(nameset_matches, ARRAY_SIZE(nameset_matches));
  return xt_register_targets(nameset_targets, ARRAY_SIZE(nameset_targets));
}

static void nameset_exit(void)
{
  atomic_set(&cleanup, 1);

  if (!wq) {
    goto out;
  }
  remove_proc_entry("nameset_command", init_net.proc_net);

  xt_unregister_matches(nameset_matches, ARRAY_SIZE(nameset_matches));
  xt_unregister_targets(nameset_targets, ARRAY_SIZE(nameset_targets));

  cancel_delayed_work_sync(&gc_worker_wk);
  flush_workqueue(wq);
  destroy_workqueue(wq);

out:
  destroy_all_dns_cache();
  destroy_all_match_result_cache();
  destroy_all_nameset_records();
}

module_init(nameset_init);
module_exit(nameset_exit);

MODULE_LICENSE("GPL");

