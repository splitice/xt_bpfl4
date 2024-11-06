/* Xtables module to match packets using a BPF filter.
 * Copyright 2013 Google Inc.
 * Written by Willem de Bruijn <willemb@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/filter.h>

#include <linux/netfilter/xt_bpf.h>
#include <linux/netfilter/x_tables.h>


#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
#define bpf_prog_run BPF_PROG_RUN
#endif

MODULE_AUTHOR("Mathew Heard <mheard@x4b.net>");
MODULE_DESCRIPTION("Xtables: BPF Layer4 filter match");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_bpfl4");
MODULE_ALIAS("ip6t_bpfl4");

static int bpfl4_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_bpf_info *info = par->matchinfo;
	struct sock_fprog_kern program;

	program.len = info->bpf_program_num_elem;
	program.filter = info->bpf_program;

	if (bpf_prog_create(&info->filter, &program)) {
		pr_info("bpfl4: check failed: parse error\n");
		return -EINVAL;
	}

	return 0;
}

static bool bpfl4_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	bool result;
	const struct xt_bpf_info *info = par->matchinfo;
	struct sk_buff *skb2 = (struct sk_buff *)skb;

	char* oldData = skb2->data;
	skb2->data += par->thoff;
	result = bpf_prog_run(info->filter, skb2);
	skb2->data = oldData;
	
	return result;
}

static void bpfl4_mt_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_bpf_info *info = par->matchinfo;
	bpf_prog_destroy(info->filter);
}

static struct xt_match bpfl4_mt_reg __read_mostly = {
//	{
		.name		= "bpfl4",
		.revision	= 0,
		.family		= NFPROTO_UNSPEC,
//		.proto      = IPPROTO_TCP,	
		.checkentry	= bpfl4_mt_check,
		.match		= bpfl4_mt,
		.destroy	= bpfl4_mt_destroy,
		.matchsize	= sizeof(struct xt_bpf_info),
		.me		= THIS_MODULE
//	}
};

static int __init bpfl4_mt_init(void)
{
	return xt_register_match(&bpfl4_mt_reg);
}

static void __exit bpfl4_mt_exit(void)
{
	xt_unregister_match(&bpfl4_mt_reg);
}

module_init(bpfl4_mt_init);
module_exit(bpfl4_mt_exit);