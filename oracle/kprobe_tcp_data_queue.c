#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>      /* For struct iphdr and ip_hdr() */

struct appended_data {
	u32 extra_info;
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	/* Retrieve the arguments from registers.
	 * Adjust registers if needed based on your architecture.
	 */
	struct sock *sk = (struct sock *)regs->di;  /* Unused here */
	struct sk_buff *skb = (struct sk_buff *)regs->si;

	// /* Check if the packet is long enough to have 4 appended bytes */
	// if (skb->protocol == htons(ETH_P_IP)) {
    //     struct iphdr *iph = ip_hdr(skb);
    //     if (iph && iph->protocol == IPPROTO_TCP) {
    //         struct tcphdr *tcph = tcp_hdr(skb);
    //         if (tcph->res1 & 0x8) {
    //             struct appended_data *xdata = (struct appended_data *)(skb->data + skb->len);
    //             printk(KERN_INFO "Extra data (last 4 bytes) exists, extra_info = 0x%x\n", ntohl(xdata->extra_info));
    //         } 

    //     }
	// } 
    // if (skb->protocol == htons(ETH_P_IP)) {
    //     struct iphdr *iph = ip_hdr(skb);
    //     if (iph && iph->protocol == IPPROTO_TCP) {
    //         struct tcphdr *tcph = tcp_hdr(skb);
    //         if (tcph->res1 & 0x8) {
    //             u32 extra_info;
    //             /* Assume that the appended 4 bytes are at the very end of the packet */
    //             extra_info = *(u32 *)(skb->data + skb->len);
    //             printk(KERN_INFO "Extra data FROM MODULE (last 4 bytes) exists, extra_info = 0x%x\n",
    //                 ntohl(extra_info));
    //         }
    //     }
    // }
	/* Optionally, dump the first 64 bytes (or less) of the packet */
	// print_hex_dump(KERN_INFO, "kprobe skb data: ", DUMP_PREFIX_OFFSET,
	//                16, 1, skb->data, (skb->len < 64 ? skb->len : 64), false);

	return 0;
}
static struct kprobe kp = {
    .symbol_name = "tcp_data_queue",
    .pre_handler = handler_pre,
};

static int __init kprobe_init(void)
{
    int ret;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "Kprobe registered for tcp_data_queue\n");
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "Kprobe unregistered\n");
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");