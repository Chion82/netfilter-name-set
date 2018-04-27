#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "resolv.h"
#include "local_ns_parser.h"

#define PRINTF printk

const char test_buf[] = {
  0x1d, 0x21, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
  0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
  0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x0f, 0x03, 0x77, 0x77, 0x77, 0x01,
  0x61, 0x06, 0x73, 0x68, 0x69, 0x66, 0x65, 0x6e, 0xc0, 0x16, 0xc0, 0x2b, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x00, 0xad, 0x00, 0x04, 0xb4, 0x61, 0x21, 0x6b, 0xc0, 0x2b, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x00, 0xad, 0x00, 0x04, 0xb4, 0x61, 0x21, 0x6c, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xd7, 0x3c, 0xc9, 0x4b, 0x9c, 0x51, 0x5b,
  0xc5
};

void test_parse(void) {
  ns_msg msg;
  ns_rr rr_qd, rr_an;
  int rrnum, rrmax_qd, rrmax_an, hostname_buf_size;
  char *hostname, *hostname_buf;
  u_int type;
  const u_char *rd;

  if (local_ns_initparse((const u_char *)test_buf, sizeof(test_buf), &msg) < 0) {
    PRINTF("error: local_ns_initparse\n");
  }

  rrmax_qd = ns_msg_count(msg, ns_s_qd);
  if (rrmax_qd == 0) {
    return;
  }
  rrmax_an = ns_msg_count(msg, ns_s_an);
  if (rrmax_an == 0) {
    return;
  }

  for (rrnum = 0; rrnum < rrmax_qd; rrnum++) {
    if (local_ns_parserr(&msg, ns_s_qd, rrnum, &rr_qd)) {
      PRINTF("error: local_ns_parserr\n");
      return;
    }
    hostname = ns_rr_name(rr_qd);
  }

  hostname_buf_size = strlen(hostname) + 1;
  hostname_buf = kmalloc(hostname_buf_size, GFP_ATOMIC);
  memset(hostname_buf, 0x00, hostname_buf_size);
  strcpy(hostname_buf, hostname);

  PRINTF("hostname: %s\n", hostname_buf);

  for (rrnum = 0; rrnum < rrmax_an; rrnum++) {
    if (local_ns_parserr(&msg, ns_s_an, rrnum, &rr_an)) {
      PRINTF("error: local_ns_parserr\n");
      return;
    }
    type = ns_rr_type(rr_an);
    rd = ns_rr_rdata(rr_an);

    if (type == ns_t_a && rd != NULL) {
      PRINTF("A result: %pI4\n", (struct __be32 *)rd);
    }
  }

  kfree(hostname_buf);
}

int init_test_module(void) {

  test_parse();

  return 0;

}

void exit_test_module(void) {

}

module_init(init_test_module);
module_exit(exit_test_module);
