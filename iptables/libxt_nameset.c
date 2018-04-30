#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>

#define MAX_SET_NAME_LENGTH (20)
#define NAME_SET_BUF_CAP (MAX_SET_NAME_LENGTH + 1)

enum {
  O_SRC = 0,
  O_DST,
  O_SET_NAME,
  F_SRC = 1 << O_SRC,
  F_DST = 1 << O_DST,
  F_SET_NAME = 1 << O_SET_NAME,
};

enum {
  XT_NAMESET_HOOK_DNS_RESPONSE = 1 << 0,
  XT_NAMESET_SRC = 1 << 1,
  XT_NAMESET_DST = 1 << 2,
  XT_NAMESET_MATCH_INVERT = 1 << 3,
};

struct xt_nameset_info {
  char set_name[NAME_SET_BUF_CAP];
  uint8_t flags;
};

static const struct xt_option_entry nameset_match_opts[] = {
  {.name = "nameset-src", .id = O_SRC, .type = XTTYPE_NONE, .excl = F_DST},
  {.name = "nameset-dst", .id = O_DST, .type = XTTYPE_NONE, .excl = F_SRC},
  {.name = "match-set", .id = O_SET_NAME, .type = XTTYPE_STRING,
    .flags = XTOPT_MAND | XTOPT_INVERT},
  XTOPT_TABLEEND,
};

static void nameset_match_init(struct xt_entry_match *match)
{
  struct xt_nameset_info *info = (struct xt_nameset_info*)match->data;
  memset(info->set_name, 0x00, NAME_SET_BUF_CAP);
  info->flags = XT_NAMESET_SRC;
}

static void nameset_match_parse(struct xt_option_call *cb)
{
  struct xt_nameset_info *info = cb->data;

  xtables_option_parse(cb);

  switch (cb->entry->id) {
  case O_SRC:
    info->flags |= XT_NAMESET_SRC;
    info->flags &= ~XT_NAMESET_DST;
    break;
  case O_DST:
    info->flags |= XT_NAMESET_DST;
    info->flags &= ~XT_NAMESET_SRC;
    break;
  case O_SET_NAME:
    if (strlen(cb->arg) <= 0 || strlen(cb->arg) > MAX_SET_NAME_LENGTH) {
      xtables_error(PARAMETER_PROBLEM, "invalid set name (should be <= %d bytes)",
        MAX_SET_NAME_LENGTH);
      break;
    }
    memset(info->set_name, 0x00, NAME_SET_BUF_CAP);
    strncpy(info->set_name, cb->arg, MAX_SET_NAME_LENGTH);
    if (cb->invert)
      info->flags |= XT_NAMESET_MATCH_INVERT;
    break;
  }
}

static void nameset_match_check(struct xt_fcheck_call *cb)
{

}

static void nameset_match_print(const void *ip, const struct xt_entry_match *match,
                         int numeric)
{
  const struct xt_nameset_info *info = (const struct xt_nameset_info *)match->data;
  if (info->flags & XT_NAMESET_SRC) {
    printf(" nameset-src");
  }
  if (info->flags & XT_NAMESET_DST) {
    printf(" nameset-dst");
  }
  if (info->flags & XT_NAMESET_MATCH_INVERT) {
    printf(" !");
  }
  printf(" match-set %s", info->set_name);
}

static void nameset_match_save(const void *ip, const struct xt_entry_match *match)
{
  const struct xt_nameset_info *info = (const struct xt_nameset_info *)match->data;
  if (info->flags & XT_NAMESET_SRC) {
    printf(" --nameset-src");
  }
  if (info->flags & XT_NAMESET_DST) {
    printf(" --nameset-dst");
  }
  if (info->flags & XT_NAMESET_MATCH_INVERT) {
    printf(" !");
  }
  printf(" --match-set %s", info->set_name);
}

static void nameset_match_help(void)
{

}


static struct xtables_match nameset_matches[] = {
  {
    .family = NFPROTO_IPV4,
    .name = "nameset",
    .version  = XTABLES_VERSION,
    .size = XT_ALIGN(sizeof(struct xt_nameset_info)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_nameset_info)),
    .init = nameset_match_init,
    .x6_options = nameset_match_opts,
    .x6_fcheck = nameset_match_check,
    .x6_parse = nameset_match_parse,
    .print = nameset_match_print,
    .save = nameset_match_save,
    .help = nameset_match_help,
  },
};

void _init(void)
{
  xtables_register_matches(nameset_matches, ARRAY_SIZE(nameset_matches));
}
