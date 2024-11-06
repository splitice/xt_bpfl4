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

#include "xt_cbpf.h"
#include <linux/netfilter/x_tables.h>


#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
#define bpf_prog_run BPF_PROG_RUN
#endif

MODULE_AUTHOR("Mathew Heard <mheard@x4b.net>");
MODULE_DESCRIPTION("Xtables: BPF Layer4 filter match");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_cbpf");
MODULE_ALIAS("ip6t_cbpf");

static int cbpf_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_cbpf_info *info = par->matchinfo;
	struct sock_fprog_kern program;

	program.len = info->bpf_program_num_elem;
	program.filter = info->bpf_program;

	if (bpf_prog_create(&info->filter, &program)) {
		pr_info("cbpf: check failed: parse error\n");
		return -EINVAL;
	}

	return 0;
}

static bool cbpf_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	bool result;
	const struct xt_cbpf_info *info = par->matchinfo;
	
	result = bpf_prog_run(info->filter, skb);
	
	return result;
}

static void cbpf_mt_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_cbpf_info *info = par->matchinfo;
	bpf_prog_destroy(info->filter);
}

static struct xt_match cbpf_mt_reg __read_mostly = {
//	{
		.name		= "cbpf",
		.revision	= 0,
		.family		= NFPROTO_UNSPEC,
//		.proto      = IPPROTO_TCP,	
		.checkentry	= cbpf_mt_check,
		.match		= cbpf_mt,
		.destroy	= cbpf_mt_destroy,
		.matchsize	= sizeof(struct xt_cbpf_info),
		.me		= THIS_MODULE
//	}
};

static int __init cbpf_mt_init(void)
{
	return xt_register_match(&cbpf_mt_reg);
}

static void __exit cbpf_mt_exit(void)
{
	xt_unregister_match(&cbpf_mt_reg);
}

module_init(cbpf_mt_init);
module_exit(cbpf_mt_exit);