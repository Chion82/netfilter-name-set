#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>

#define MAX_SET_NAME_LENGTH (20)
#define NAME_SET_BUF_CAP (MAX_SET_NAME_LENGTH + 1)

enum {
  O_HOOK_DNS_RESPONSE = 0,
};

enum {
  XT_NAMESET_HOOK_DNS_RESPONSE = 1 << 0,
  XT_NAMESET_SRC = 1 << 1,
  XT_NAMESET_DST = 1 << 2,
  XT_NAMESET_MATCH_INVERTED = 1 << 3,
};

struct xt_nameset_info {
  char set_name[NAME_SET_BUF_CAP];
  uint8_t flags;
};

static const struct xt_option_entry NAMESET_target_opts[] = {
  {.name = "hook-dns-response", .id = O_HOOK_DNS_RESPONSE, .type = XTTYPE_NONE,
    .flags = XTOPT_MAND},
  XTOPT_TABLEEND,
};

static void NAMESET_target_init(struct xt_entry_target *target)
{
  struct xt_nameset_info *info = (struct xt_nameset_info*)target->data;
  memset(info->set_name, 0x00, NAME_SET_BUF_CAP);
  info->flags = 0;
}

static void NAMESET_target_parse(struct xt_option_call *cb)
{
  struct xt_nameset_info *info = cb->data;

  xtables_option_parse(cb);

  switch (cb->entry->id) {
  case O_HOOK_DNS_RESPONSE:
    info->flags |= XT_NAMESET_HOOK_DNS_RESPONSE;
    break;
  }
}

static void NAMESET_target_check(struct xt_fcheck_call *cb)
{

}

static void NAMESET_target_print(const void *ip, const struct xt_entry_target *target,
                         int numeric)
{
  const struct xt_nameset_info *info = (const struct xt_nameset_info *)target->data;
  if (info->flags & XT_NAMESET_HOOK_DNS_RESPONSE) {
    printf(" hook_dns_response");
  }
}

static void NAMESET_target_save(const void *ip, const struct xt_entry_target *target)
{
  const struct xt_nameset_info *info = (const struct xt_nameset_info *)target->data;
  if (info->flags & XT_NAMESET_HOOK_DNS_RESPONSE) {
    printf(" --hook-dns-response");
  }
}

static void NAMESET_target_help(void)
{

}

static struct xtables_target NAMESET_targets[] = {
  {
    .family = NFPROTO_IPV4,
    .name = "NAMESET",
    .version  = XTABLES_VERSION,
    .size = XT_ALIGN(sizeof(struct xt_nameset_info)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_nameset_info)),
    .init = NAMESET_target_init,
    .x6_options = NAMESET_target_opts,
    .x6_fcheck = NAMESET_target_check,
    .x6_parse = NAMESET_target_parse,
    .print = NAMESET_target_print,
    .save = NAMESET_target_save,
    .help = NAMESET_target_help,
  },
};

void _init(void)
{
  xtables_register_targets(NAMESET_targets, ARRAY_SIZE(NAMESET_targets));
}
