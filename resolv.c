#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>

#include "resolv.h"

static const char digits[] = "0123456789";

static int
labellen(const u_char *lp)
{
  int bitlen;
  u_char l = *lp;

  if ((l & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
    /* should be avoided by the caller */
    return(-1);
  }

  if ((l & NS_CMPRSFLGS) == NS_TYPE_ELT) {
    if (l == DNS_LABELTYPE_BITSTRING) {
      if ((bitlen = *(lp + 1)) == 0)
        bitlen = 256;
      return((bitlen + 7 ) / 8 + 1);
    }
    return(-1); /*%< unknwon ELT */
  }
  return(l);
}

/*%
 *  Thinking in noninternationalized USASCII (per the DNS spec),
 *  is this characted special ("in need of quoting") ?
 *
 * return:
 *\li boolean.
 */
static int
special(int ch) {
  switch (ch) {
  case 0x22: /*%< '"' */
  case 0x2E: /*%< '.' */
  case 0x3B: /*%< ';' */
  case 0x5C: /*%< '\\' */
  case 0x28: /*%< '(' */
  case 0x29: /*%< ')' */
  /* Special modifiers in zone files. */
  case 0x40: /*%< '@' */
  case 0x24: /*%< '$' */
    return (1);
  default:
    return (0);
  }
}

/*%
 *  Thinking in noninternationalized USASCII (per the DNS spec),
 *  is this character visible and not a space when printed ?
 *
 * return:
 *\li boolean.
 */
static int
printable(int ch) {
  return (ch > 0x20 && ch < 0x7f);
}

static int
decode_bitstring(const unsigned char **cpp, char *dn, const char *eom)
{
  const unsigned char *cp = *cpp;
  char *beg = dn, tc;
  int b, blen, plen, i;

  if ((blen = (*cp & 0xff)) == 0)
    blen = 256;
  plen = (blen + 3) / 4;
  plen += sizeof("\\[x/]") + (blen > 99 ? 3 : (blen > 9) ? 2 : 1);
  if (dn + plen >= eom)
    return(-1);

  cp++;
  i = SPRINTF((dn, "\\[x"));
  if (i < 0)
    return (-1);
  dn += i;
  for (b = blen; b > 7; b -= 8, cp++) {
    i = SPRINTF((dn, "%02x", *cp & 0xff));
    if (i < 0)
      return (-1);
    dn += i;
  }
  if (b > 4) {
    tc = *cp++;
    i = SPRINTF((dn, "%02x", tc & (0xff << (8 - b))));
    if (i < 0)
      return (-1);
    dn += i;
  } else if (b > 0) {
    tc = *cp++;
    i = SPRINTF((dn, "%1x",
             ((tc >> 4) & 0x0f) & (0x0f << (4 - b))));
    if (i < 0)
      return (-1);
    dn += i;
  }
  i = SPRINTF((dn, "/%d]", blen));
  if (i < 0)
    return (-1);
  dn += i;

  *cpp = cp;
  return(dn - beg);
}

/*%
 *  Convert an encoded domain name to printable ascii as per RFC1035.
 * return:
 *\li Number of bytes written to buffer, or -1 (with errno set)
 *
 * notes:
 *\li The root is returned as "."
 *\li All other domains are returned in non absolute form
 */
int
ns_name_ntop(const u_char *src, char *dst, size_t dstsiz)
{
  const u_char *cp;
  char *dn, *eom;
  u_char c;
  u_int n;
  int l;

  cp = src;
  dn = dst;
  eom = dst + dstsiz;

  while ((n = *cp++) != 0) {
    if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
      /* Some kind of compression pointer. */
      // __set_errno (EMSGSIZE);
      return (-1);
    }
    if (dn != dst) {
      if (dn >= eom) {
        // __set_errno (EMSGSIZE);
        return (-1);
      }
      *dn++ = '.';
    }
    if ((l = labellen(cp - 1)) < 0) {
      // __set_errno (EMSGSIZE);
      return(-1);
    }
    if (dn + l >= eom) {
      // __set_errno (EMSGSIZE);
      return (-1);
    }
    if ((n & NS_CMPRSFLGS) == NS_TYPE_ELT) {
      int m;

      if (n != DNS_LABELTYPE_BITSTRING) {
        /* XXX: labellen should reject this case */
        // __set_errno (EINVAL);
        return(-1);
      }
      if ((m = decode_bitstring(&cp, dn, eom)) < 0)
      {
        // __set_errno (EMSGSIZE);
        return(-1);
      }
      dn += m;
      continue;
    }
    for ((void)NULL; l > 0; l--) {
      c = *cp++;
      if (special(c)) {
        if (dn + 1 >= eom) {
          // __set_errno (EMSGSIZE);
          return (-1);
        }
        *dn++ = '\\';
        *dn++ = (char)c;
      } else if (!printable(c)) {
        if (dn + 3 >= eom) {
          // __set_errno (EMSGSIZE);
          return (-1);
        }
        *dn++ = '\\';
        *dn++ = digits[c / 100];
        *dn++ = digits[(c % 100) / 10];
        *dn++ = digits[c % 10];
      } else {
        if (dn >= eom) {
          // __set_errno (EMSGSIZE);
          return (-1);
        }
        *dn++ = (char)c;
      }
    }
  }
  if (dn == dst) {
    if (dn >= eom) {
      // __set_errno (EMSGSIZE);
      return (-1);
    }
    *dn++ = '.';
  }
  if (dn >= eom) {
    // __set_errno (EMSGSIZE);
    return (-1);
  }
  *dn++ = '\0';
  return (dn - dst);
}

/*%
 *  Unpack a domain name from a message, source may be compressed.
 *
 * return:
 *\li -1 if it fails, or consumed octets if it succeeds.
 */
int
ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src,
         u_char *dst, size_t dstsiz)
{
  const u_char *srcp, *dstlim;
  u_char *dstp;
  int n, len, checked, l;

  len = -1;
  checked = 0;
  dstp = dst;
  srcp = src;
  dstlim = dst + dstsiz;
  if (srcp < msg || srcp >= eom) {
    // __set_errno (EMSGSIZE);
    return (-1);
  }
  /* Fetch next label in domain name. */
  while ((n = *srcp++) != 0) {
    /* Check for indirection. */
    switch (n & NS_CMPRSFLGS) {
    case 0:
    case NS_TYPE_ELT:
      /* Limit checks. */
      if ((l = labellen(srcp - 1)) < 0) {
        // __set_errno (EMSGSIZE);
        return(-1);
      }
      if (dstp + l + 1 >= dstlim || srcp + l >= eom) {
        // __set_errno (EMSGSIZE);
        return (-1);
      }
      checked += l + 1;
      *dstp++ = n;
      memcpy(dstp, srcp, l);
      dstp += l;
      srcp += l;
      break;

    case NS_CMPRSFLGS:
      if (srcp >= eom) {
        // __set_errno (EMSGSIZE);
        return (-1);
      }
      if (len < 0)
        len = srcp - src + 1;
      srcp = msg + (((n & 0x3f) << 8) | (*srcp & 0xff));
      if (srcp < msg || srcp >= eom) {  /*%< Out of range. */
        // __set_errno (EMSGSIZE);
        return (-1);
      }
      checked += 2;
      /*
       * Check for loops in the compressed name;
       * if we've looked at the whole message,
       * there must be a loop.
       */
      if (checked >= eom - msg) {
        // __set_errno (EMSGSIZE);
        return (-1);
      }
      break;

    default:
      // __set_errno (EMSGSIZE);
      return (-1);      /*%< flag error */
    }
  }
  *dstp = '\0';
  if (len < 0)
    len = srcp - src;
  return (len);
}

/*%
 *  Expand compressed domain name to presentation format.
 *
 * return:
 *\li Number of bytes read out of `src', or -1 (with errno set).
 *
 * note:
 *\li Root domain returns as "." not "".
 */
int
ns_name_uncompress(const u_char *msg, const u_char *eom, const u_char *src,
       char *dst, size_t dstsiz)
{
  u_char tmp[NS_MAXCDNAME];
  int n;

  if ((n = ns_name_unpack(msg, eom, src, tmp, sizeof tmp)) == -1)
    return (-1);
  if (ns_name_ntop(tmp, dst, dstsiz) == -1)
    return (-1);
  return (n);
}

/*
 * Expand compressed domain name 'comp_dn' to full domain name.
 * 'msg' is a pointer to the begining of the message,
 * 'eomorig' points to the first location after the message,
 * 'exp_dn' is a pointer to a buffer of size 'length' for the result.
 * Return size of compressed name or -1 if there was an error.
 */
int
dn_expand(const u_char *msg, const u_char *eom, const u_char *src,
    char *dst, int dstsiz)
{
  int n = ns_name_uncompress(msg, eom, src, dst, (size_t)dstsiz);

  if (n > 0 && dst[0] == '.')
    dst[0] = '\0';
  return (n);
}

