/*
 *	"LABEL" target extension for iptables
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <xtables.h>
#include <linux/elmac.h>




enum {
	FL_LEVEL_USED = 1 << 0,
	FL_CAT_USED = 1 << 1,
};

/* Function which prints out usage message. */
static void label_tg_help(void)
{
	printf(
	"LABEL target options:\n"
	"  --level value set elmac level\n"
	"  --cat value set elmac category\n"
	);
}

static const struct option label_tg_opts[] = {
	{.name = "level",     .has_arg = true, .val = '1'},
	{.name = "cat",     .has_arg = true, .val = '2'},
	{NULL},
};

/* Initialize the target. */
static void label_tg_init(struct xt_entry_target *t)
{
	elmac_context_t *label = (void *)t->data;

	label->mac.level = 0;
	label->mac.category = 0;
	label->attr = 0;
}

static int label_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_target **target)
{
	elmac_context_t *label = (void *)(*target)->data;
	unsigned int n;

	switch (c) {
	
	case '1':
		xtables_param_act(XTF_ONLY_ONCE, "LABEL", "level", *flags & FL_LEVEL_USED);
		xtables_param_act(XTF_NO_INVERT, "LABEL", "level", invert);
		if (!xtables_strtoui(optarg, NULL, &n, 0, UINT8_MAX))
			xtables_param_act(XTF_BAD_VALUE, "LABEL", "level", optarg);
		label->mac.level = n;
		*flags |= FL_LEVEL_USED;
		return true;
	
	
	case '2':
		xtables_param_act(XTF_ONLY_ONCE, "LABEL", "cat", *flags & FL_CAT_USED);
		xtables_param_act(XTF_NO_INVERT, "LABEL", "level", invert);
		if (!xtables_strtoui(optarg, NULL, &n, 0, UINT64_MAX))
			xtables_param_act(XTF_BAD_VALUE, "LABEL", "cat", optarg);
		label->mac.category = n;
		*flags |= FL_CAT_USED;
		return true;
	}

	return false;
}

static void label_tg_check(unsigned int flags)
{
	if (!(flags & FL_LEVEL_USED))
		xtables_error(PARAMETER_PROBLEM,
		           "LABEL target: Parameter --level is required");
	if (!(flags & FL_CAT_USED))
		xtables_error(PARAMETER_PROBLEM,
		           "LABEL target: Parameter --cat is required");
}

static void
label_tg_save(const void *entry, const struct xt_entry_target *target)
{
	elmac_context_t *label = (const void *)target->data;

	if (label->mac.level != 0)
		printf(" --level %u ", (unsigned int)label->mac.level);
		
	if (label->mac.category != 0)
		printf(" --cat %u ", (unsigned int)label->mac.category);
}

static void
label_tg_print(const void *entry, const struct xt_entry_target *target,
                int numeric)
{
	printf(" -j LABEL");
	label_tg_save(entry, target);
}

static struct xtables_target label_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "LABEL",
	.family        = NFPROTO_UNSPEC,
	.revision      = 0,
	.size          = XT_ALIGN(sizeof(elmac_context_t)),
	.userspacesize = XT_ALIGN(sizeof(elmac_context_t)),
	.help          = label_tg_help,
	.init          = label_tg_init,
	.parse         = label_tg_parse,
	.final_check   = label_tg_check,
	.print         = label_tg_print,
	.save          = label_tg_save,
	.extra_opts    = label_tg_opts,
};

static __attribute__((constructor)) void label_tg_ldr(void)
{
	xtables_register_target(&label_tg_reg);
}
