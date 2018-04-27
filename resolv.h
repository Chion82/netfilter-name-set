#define uchar unsigned char

/*
 * Define constants based on RFC 883, RFC 1034, RFC 1035
 */
#define NS_PACKETSZ 512 /*%< default UDP packet size */
#define NS_MAXDNAME 1025  /*%< maximum domain name */
#define NS_MAXMSG 65535 /*%< maximum message size */
#define NS_MAXCDNAME  255 /*%< maximum compressed domain name */
#define NS_MAXLABEL 63  /*%< maximum length of domain label */
#define NS_HFIXEDSZ 12  /*%< #/bytes of fixed data in header */
#define NS_QFIXEDSZ 4 /*%< #/bytes of fixed data in query */
#define NS_RRFIXEDSZ  10  /*%< #/bytes of fixed data in r record */
#define NS_INT32SZ  4 /*%< #/bytes of data in a u_int32_t */
#define NS_INT16SZ  2 /*%< #/bytes of data in a u_int16_t */
#define NS_INT8SZ 1 /*%< #/bytes of data in a u_int8_t */
#define NS_INADDRSZ 4 /*%< IPv4 T_A */
#define NS_IN6ADDRSZ  16  /*%< IPv6 T_AAAA */
#define NS_CMPRSFLGS  0xc0  /*%< Flag bits indicating name compression. */
#define NS_DEFAULTPORT  53  /*%< For both TCP and UDP. */

#define SPRINTF(x) ((size_t)sprintf x)

#define NS_TYPE_ELT     0x40 /*%< EDNS0 extended label type */
#define DNS_LABELTYPE_BITSTRING   0x41

/* Accessor macros - this is part of the public interface. */

#define ns_msg_id(handle) ((handle)._id + 0)
#define ns_msg_base(handle) ((handle)._msg + 0)
#define ns_msg_end(handle) ((handle)._eom + 0)
#define ns_msg_size(handle) ((handle)._eom - (handle)._msg)
#define ns_msg_count(handle, section) ((handle)._counts[section] + 0)

/* Accessor macros - this is part of the public interface. */
#define ns_rr_name(rr)  (((rr).name[0] != '\0') ? (rr).name : ".")
#define ns_rr_type(rr)  ((ns_type)((rr).type + 0))
#define ns_rr_class(rr) ((ns_class)((rr).rr_class + 0))
#define ns_rr_ttl(rr) ((rr).ttl + 0)
#define ns_rr_rdlen(rr) ((rr).rdlength + 0)
#define ns_rr_rdata(rr) ((rr).rdata + 0)

#define INT32SZ   NS_INT32SZ
#define INT16SZ   NS_INT16SZ

# undef NS_GET16
# define NS_GET16(s, cp) \
  do {                        \
    const uint16_t *t_cp = (const uint16_t *) (cp);           \
    (s) = be16_to_cpu(*t_cp);                  \
    (cp) += NS_INT16SZ;                   \
  } while (0)

# undef NS_GET32
# define NS_GET32(l, cp) \
  do {                        \
    const uint32_t *t_cp = (const uint32_t *) (cp);           \
    (l) = be32_to_cpu(*t_cp);                  \
    (cp) += NS_INT32SZ;                   \
  } while (0)

/*
 * These can be expanded with synonyms, just keep ns_parse.c:ns_parserecord()
 * in synch with it.
 */
typedef enum __ns_sect {
  ns_s_qd = 0,    /*%< Query: Question. */
  ns_s_zn = 0,    /*%< Update: Zone. */
  ns_s_an = 1,    /*%< Query: Answer. */
  ns_s_pr = 1,    /*%< Update: Prerequisites. */
  ns_s_ns = 2,    /*%< Query: Name servers. */
  ns_s_ud = 2,    /*%< Update: Update. */
  ns_s_ar = 3,    /*%< Query|Update: Additional records. */
  ns_s_max = 4
} ns_sect;

/*%
 * This is a message handle.  It is caller allocated and has no dynamic data.
 * This structure is intended to be opaque to all but ns_parse.c, thus the
 * leading _'s on the member names.  Use the accessor functions, not the _'s.
 */
typedef struct __ns_msg {
  const u_char  *_msg, *_eom;
  u_int16_t _id, _flags, _counts[ns_s_max];
  const u_char  *_sections[ns_s_max];
  ns_sect   _sect;
  int   _rrnum;
  const u_char  *_msg_ptr;
} ns_msg;

/*%
 * This is a parsed record.  It is caller allocated and has no dynamic data.
 */
typedef struct __ns_rr {
  char    name[NS_MAXDNAME];
  u_int16_t type;
  u_int16_t rr_class;
  u_int32_t ttl;
  u_int16_t rdlength;
  const u_char *  rdata;
} ns_rr;

/*%
 * Currently defined type values for resources and queries.
 */
typedef enum __ns_type {
  ns_t_invalid = 0, /*%< Cookie. */
  ns_t_a = 1,   /*%< Host address. */
  ns_t_ns = 2,    /*%< Authoritative server. */
  ns_t_md = 3,    /*%< Mail destination. */
  ns_t_mf = 4,    /*%< Mail forwarder. */
  ns_t_cname = 5,   /*%< Canonical name. */
  ns_t_soa = 6,   /*%< Start of authority zone. */
  ns_t_mb = 7,    /*%< Mailbox domain name. */
  ns_t_mg = 8,    /*%< Mail group member. */
  ns_t_mr = 9,    /*%< Mail rename name. */
  ns_t_null = 10,   /*%< Null resource record. */
  ns_t_wks = 11,    /*%< Well known service. */
  ns_t_ptr = 12,    /*%< Domain name pointer. */
  ns_t_hinfo = 13,  /*%< Host information. */
  ns_t_minfo = 14,  /*%< Mailbox information. */
  ns_t_mx = 15,   /*%< Mail routing information. */
  ns_t_txt = 16,    /*%< Text strings. */
  ns_t_rp = 17,   /*%< Responsible person. */
  ns_t_afsdb = 18,  /*%< AFS cell database. */
  ns_t_x25 = 19,    /*%< X_25 calling address. */
  ns_t_isdn = 20,   /*%< ISDN calling address. */
  ns_t_rt = 21,   /*%< Router. */
  ns_t_nsap = 22,   /*%< NSAP address. */
  ns_t_nsap_ptr = 23, /*%< Reverse NSAP lookup (deprecated). */
  ns_t_sig = 24,    /*%< Security signature. */
  ns_t_key = 25,    /*%< Security key. */
  ns_t_px = 26,   /*%< X.400 mail mapping. */
  ns_t_gpos = 27,   /*%< Geographical position (withdrawn). */
  ns_t_aaaa = 28,   /*%< Ip6 Address. */
  ns_t_loc = 29,    /*%< Location Information. */
  ns_t_nxt = 30,    /*%< Next domain (security). */
  ns_t_eid = 31,    /*%< Endpoint identifier. */
  ns_t_nimloc = 32, /*%< Nimrod Locator. */
  ns_t_srv = 33,    /*%< Server Selection. */
  ns_t_atma = 34,   /*%< ATM Address */
  ns_t_naptr = 35,  /*%< Naming Authority PoinTeR */
  ns_t_kx = 36,   /*%< Key Exchange */
  ns_t_cert = 37,   /*%< Certification record */
  ns_t_a6 = 38,   /*%< IPv6 address (deprecated, use ns_t_aaaa) */
  ns_t_dname = 39,  /*%< Non-terminal DNAME (for IPv6) */
  ns_t_sink = 40,   /*%< Kitchen sink (experimentatl) */
  ns_t_opt = 41,    /*%< EDNS0 option (meta-RR) */
  ns_t_apl = 42,    /*%< Address prefix list (RFC3123) */
  ns_t_tkey = 249,  /*%< Transaction key */
  ns_t_tsig = 250,  /*%< Transaction signature. */
  ns_t_ixfr = 251,  /*%< Incremental zone transfer. */
  ns_t_axfr = 252,  /*%< Transfer zone of authority. */
  ns_t_mailb = 253, /*%< Transfer mailbox records. */
  ns_t_maila = 254, /*%< Transfer mail agent records. */
  ns_t_any = 255,   /*%< Wildcard match. */
  ns_t_zxfr = 256,  /*%< BIND-specific, nonstandard. */
  ns_t_max = 65536
} ns_type;

int
dn_expand(const u_char *msg, const u_char *eom, const u_char *src,
    char *dst, int dstsiz);
