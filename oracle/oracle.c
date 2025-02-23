
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/ip.h>  /* For struct iphdr and ip_hdr() */
#include <linux/tcp.h> /* For struct tcphdr and tcp_hdr(), also inlcudes oracle_tag*/
#include <net/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/netlink.h> /* For struct netlink_ext_ack */
#include <linux/string.h>
// TODO: find out if i can get rid of this, i don't like it here, it sucks



struct tbf_sched_data {
	/* Parameters */
		u32		limit;		/* Maximal length of backlog: bytes */
		u32		max_size;
		s64		buffer;		/* Token bucket depth/rate: MUST BE >= MTU/B */
		s64		mtu;
		struct psched_ratecfg rate;
		struct psched_ratecfg peak;
	
	/* Variables */
		s64	tokens;			/* Current number of B tokens */
		s64	ptokens;		/* Current number of P tokens */
		s64	t_c;			/* Time check-point */
		struct Qdisc	*qdisc;		/* Inner qdisc, default - bfifo queue */
		struct qdisc_watchdog watchdog;	/* Watchdog timer */
};

// struct oracle_tag {
// 	u64 rate;
// 	u32 backlog;
// 	u32 flows;
// };

struct oracle_sched_data{
	u64 txBytes;
	u64 rate;

};



/* Updated init function: added netlink_ext_ack *extack parameter */
static int oracle_init(struct Qdisc *sch, struct nlattr *opt,
					   struct netlink_ext_ack *extack)
{
	struct Qdisc *parent_qdisc;
	const struct Qdisc_ops *parentops;
	struct tbf_sched_data *tbf_data;
	struct oracle_sched_data *q = qdisc_priv(sch);

	parent_qdisc = rcu_dereference(sch->dev_queue->qdisc);
	if (sch->parent) 
		parentops = rcu_dereference(parent_qdisc->ops);
	else
		goto noparent;


	if (!strcmp(parentops->id, "tbf") == 0)
		goto noparent; 
		
		// printk(KERN_INFO "MODULE: Type of tbf_data->rate: %zu\n", tbf_data->rate.rate_bytes_ps);
		// printk(KERN_INFO "MODULE: Parent TBF limit: %u\n", tbf_data->rate);
		
		// printk(KERN_INFO "MODULE: Parent TBF id: %s\n", parentops->id);
	tbf_data = qdisc_priv(parent_qdisc);
	q->rate = tbf_data->rate.rate_bytes_ps;
	
	//printk(KERN_INFO "MODULE: Parent TBF identified and rate set to : %u \n", tbf_data->rate.rate_bytes_ps);



	qdisc_reset(sch);
	return 0;
noparent:
	printk(KERN_INFO "MODULE: Failed to start ");
	qdisc_reset(sch);
	return 0;
}

static void oracle_reset(struct Qdisc *sch)
{
	qdisc_reset_queue(sch);
}

static void oracle_destroy(struct Qdisc *sch)
{
	oracle_reset(sch);
}

static struct sk_buff *oracle_peek(struct Qdisc *sch)
{
	return qdisc_peek_head(sch);
}

static struct sk_buff *oracle_dequeue(struct Qdisc *sch)
{



	return qdisc_dequeue_head(sch);

}

static netdev_tx_t oracle_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct oracle_sched_data *q = qdisc_priv(sch);
	struct sk_buff *nskb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct oracle_tag *tag;
	if (skb_shared(skb)) {
		skb = skb_unshare(skb, GFP_ATOMIC);
		if (!skb) {
			printk(KERN_INFO "Failed to unshare skb\n");
			sch->qstats.drops++;
			return NET_XMIT_DROP;
		}
	}
	
    if (!skb) {
		printk(KERN_INFO "MODULE: NOT SKPBBBBBB \n");
        goto fail;
    }
	if (skb_tailroom(skb) < sizeof(struct oracle_tag)){
		nskb = skb_copy_expand(skb, skb_headroom(skb), sizeof(struct oracle_tag), GFP_ATOMIC);
		if (!nskb)
		{
			printk(KERN_INFO "MODULE: !nskb failed \n");
			sch->qstats.drops++;
			kfree_skb(skb);
			return NET_XMIT_DROP; 
		}
		kfree_skb(skb);
		skb = nskb;
	}

	
	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);
	tcph->res1 |= 0x8;

	tag = skb_put_zero(skb, sizeof(struct oracle_tag));
	tag->rate = q->rate;
	tag->backlog = qdisc_qlen(sch);
	tag->flows = 2;
	
	
	//print_hex_dump(KERN_INFO, "MODULE: Packet Data: ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);
	//printk(KERN_INFO "MODULE: skb after expansion, len: %u\n", skb->len);


	return qdisc_enqueue_tail(skb, sch);
fail: 
	printk(KERN_INFO "MODULE: check failed");
	return qdisc_enqueue_tail(skb, sch);
}

static struct Qdisc_ops oracle_qdisc_ops __read_mostly = {
	.id = "oracle",
	.priv_size = sizeof(struct oracle_sched_data),
	.init = oracle_init,
	.enqueue = oracle_enqueue,
	.dequeue = oracle_dequeue,
	.peek = oracle_peek,
	.reset = oracle_reset,
	.destroy = oracle_destroy,
	.owner = THIS_MODULE,
};

static int __init oracle_module_init(void)
{
	printk(KERN_INFO "MODULE: Oracle qdisc module loaded\n");
	return register_qdisc(&oracle_qdisc_ops);
}

static void __exit oracle_module_exit(void)
{
	unregister_qdisc(&oracle_qdisc_ops);
	printk(KERN_INFO "MODULE: Oracle qdisc module unloaded\n");
}

module_init(oracle_module_init);
module_exit(oracle_module_exit);

MODULE_AUTHOR("Mihai Mazilu");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Queue disc that tags packets, must be used ontp	of tbf");
