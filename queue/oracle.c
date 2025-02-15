

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/netlink.h> /* For struct netlink_ext_ack */

struct oracle_sched_data {
	u32 packet_count;
};

/* Updated init function: added netlink_ext_ack *extack parameter */
static int oracle_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct oracle_sched_data *q = qdisc_priv(sch);

	/* Initialize the underlying FIFO queue */
	qdisc_reset(sch);
	q->packet_count = 0;
	return 0;
}

static void oracle_reset(struct Qdisc *sch)
{
	struct oracle_sched_data *q = qdisc_priv(sch);

	qdisc_reset_queue(sch);
	q->packet_count = 0;
}

static void oracle_destroy(struct Qdisc *sch)
{
	oracle_reset(sch);
}

static struct sk_buff *oracle_dequeue(struct Qdisc *sch)
{
	return qdisc_dequeue_head(sch);
}

static struct sk_buff *oracle_peek(struct Qdisc *sch)
{
	return qdisc_peek_head(sch);
}

static netdev_tx_t oracle_enqueue(struct sk_buff *skb, struct Qdisc *sch,
	struct sk_buff **to_free)
{
	// printk(KERN_INFO "Before: skb->len = %u, tailroom = %u\n", skb->len, skb_tailroom(skb));
	struct oracle_sched_data *q = qdisc_priv(sch);
	struct sk_buff *nskb;
	/* Unshare the skb if necessary */
	if (skb_shared(skb)) {
		skb = skb_unshare(skb, GFP_ATOMIC);
		if (!skb) {
			printk(KERN_INFO "Failed to unshare skb\n");
			sch->qstats.drops++;
			return NET_XMIT_DROP;
		}
	}
	
	q->packet_count++;

	/* Ensure there is at least 1 byte of tailroom.
	* Instead of in-place expansion, use skb_copy_expand to create a new skb
	* with extra tailroom. This can help avoid in-place modifications that
	* may crash in some contexts.
	*/
	if (skb_tailroom(skb) < 1) {
		nskb = skb_copy_expand(skb, skb_headroom(skb), 1, GFP_ATOMIC);
		if (!nskb) {
			printk(KERN_INFO "!nskb failed \n");
			sch->qstats.drops++;
			kfree_skb(skb);
			return NET_XMIT_DROP; /* Drop packet if expansion fails */
		}
		printk(KERN_INFO "sizeof(nskb) = %u \n", nskb->len);
		kfree_skb(skb);
		skb = nskb;
}

	/* Append one byte to the packet with the packet count (modulo 256) */
	{
		unsigned char *p = skb_put(skb, 1);
		*p = (unsigned char)(0x69);
	}
	printk(KERN_INFO "Packet content (len=%u):\n", skb->len);
	print_hex_dump(KERN_INFO, "  ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);
	//printk(KERN_INFO "After: skb->len = %u, tailroom = %u\n", skb->len, skb_tailroom(skb));
	/* Enqueue the packet with the extra byte appended */
	return qdisc_enqueue_tail(skb, sch);
}






static struct Qdisc_ops oracle_qdisc_ops __read_mostly = {
	.id		= "oracle",
	.priv_size	= sizeof(struct oracle_sched_data),
	.init		= oracle_init,
	.enqueue	= oracle_enqueue,
	.dequeue	= oracle_dequeue,
	.peek		= oracle_peek,
	.reset		= oracle_reset,
	.destroy	= oracle_destroy,
	.owner		= THIS_MODULE,
};

static int __init oracle_module_init(void)
{
	printk(KERN_INFO "Oracle qdisc module loaded\n");
	return register_qdisc(&oracle_qdisc_ops);
}

static void __exit oracle_module_exit(void)
{
	unregister_qdisc(&oracle_qdisc_ops);
	printk(KERN_INFO "Oracle qdisc module unloaded\n");
}

module_init(oracle_module_init);
module_exit(oracle_module_exit);

MODULE_AUTHOR("Oracle Qdisc Example");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A qdisc that drops every 5th packet (FIFO otherwise)");
