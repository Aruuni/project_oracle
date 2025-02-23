#include <linux/module.h>
#include <linux/random.h>
#include <net/tcp.h>

#define THR_SCALE 24
#define THR_UNIT (1 << THR_SCALE)

const char *prefix = "[snap-sat-dbg12]";


#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

struct snap
{
    /* CA state on previous ACK */
    u32 prev_ca_state : 3;
    /* prior cwnd upon entering loss recovery */
    u32 prior_cwnd;
    u32 min_rtt_us; /* min RTT in min_rtt_win_sec window */
    u64 oracle_rate_bps; /* rate from oracle */
    u32 flows;      /* number of flows, observed by oracle */
    u32 has_seen_rtt:1; /* flag to indicate if we have seen an RTT sample */  
    u32 init_cwnd:10;    
};


static u32 snap_bdp(struct sock *sk, u32 bw)
{
	struct snap *snap = inet_csk_ca(sk);
	u32 bdp;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: initial cwnd.
	 */
	if (unlikely(snap->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return snap->init_cwnd;  /* be safe: cap at initial cwnd */

    bdp = (u64)bw * snap->min_rtt_us;


	return bdp;
}
static void snap_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
    struct snap *snap = inet_csk_ca(sk);

    if (rs->rtt_us < snap->min_rtt_us)
        snap->min_rtt_us = rs->rtt_us;
}

/* converts the rate to pacing rate, applies the THR_SCALE*/
static u64 snap_rate_to_bytes_per_sec(struct sock *sk, u64 rate, int margin)
{
    unsigned int mss = tcp_sk(sk)->mss_cache + sizeof(struct oracle_tag);

    rate *= mss;
    //rate *= gain;
    //rate >>= BBR_SCALE;
    rate *= USEC_PER_SEC / 100 * (100 - margin);
    rate >>= THR_SCALE;
    rate = max(rate, 1ULL);
    return rate;
}


/* Convert bandwidth to pacing rate. */
static unsigned long snap_bw_to_pacing_rate(struct sock *sk, u32 bw)
{
	u64 rate = bw;

	rate = snap_rate_to_bytes_per_sec(sk, rate, 0);
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}


/* Initialize pacing rate  init_cwnd / RTT. */
static void snap_init_pacing_rate_from_rtt(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct snap *snap = inet_csk_ca(sk);
    u64 bw;
    u32 rtt_us;

    if (tp->srtt_us){ /* any RTT sample yet? */
        rtt_us = max(tp->srtt_us >> 3, 1U);
        snap->has_seen_rtt = 1;
    }
    else  {                      /* no RTT sample yet */
        rtt_us = USEC_PER_MSEC; /* use nominal default RTT */
    }
    bw = (u64)tcp_snd_cwnd(tp) * THR_UNIT;
    do_div(bw, rtt_us);
    sk->sk_pacing_rate = snap_bw_to_pacing_rate(sk, bw);
}

/* Pace using current bw estimate and a gain factor. */
static void snap_set_pacing_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct snap *snap = inet_csk_ca(sk);
	unsigned long rate = snap->oracle_rate_bps;

	if (unlikely(!snap->has_seen_rtt && tp->srtt_us))
		snap_init_pacing_rate_from_rtt(sk);
    // maybe optimise with flow scaling???? idk yet 
    printk(KERN_INFO "MODULE: snap_set_pacing_rate: flows: %u  rate %u", snap->flows, rate /  max(1, snap->flows));  
    sk->sk_pacing_rate = rate /  max(1, snap->flows);
}

static void snap_init(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct snap *snap = inet_csk_ca(sk);


    snap->min_rtt_us = tcp_min_rtt(tp);

    snap->has_seen_rtt = 0;
    snap_init_pacing_rate_from_rtt(sk);
    snap->prev_ca_state = TCP_CA_Open;
    snap->prior_cwnd = 0;

    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

/* Initialize cwnd to support current pacing rate (but not less then 4 packets)
 */
static void snap_set_cwnd(struct sock *sk)
{
    // struct tcp_sock* tp = tcp_sk(sk);
}

static void snap_save_cwnd(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct snap *snap = inet_csk_ca(sk);

    if (snap->prev_ca_state < TCP_CA_Recovery)
        snap->prior_cwnd = tp->snd_cwnd; /* this cwnd is good enough */
    else                                 /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
        snap->prior_cwnd = max(snap->prior_cwnd, tp->snd_cwnd);
}


void snap_update_cwnd(struct sock *sk, u32 pkts)
{
    struct tcp_sock *tp = tcp_sk(sk);
    // tp->snd_cwnd = max(tp->snd_cwnd, tp->cwnd_min);
    // tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
    tp->snd_cwnd = 1250000;

}

void snap_update_tags(struct sock *sk){
    struct tcp_sock *tp = tcp_sk(sk);
    struct snap *snap = inet_csk_ca(sk);
    snap->oracle_rate_bps = tp->oracle.rate;
    snap->flows = tp->oracle.flows;

}


static void snap_cong_control(struct sock *sk,
                              const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct snap *snap = inet_csk_ca(sk);
    // print rate sample
    u32 pkts; 


    snap_update_tags(sk);
    snap_update_min_rtt(sk, rs);



    pkts = snap->oracle_rate_bps /  (tp->mss_cache + sizeof(struct oracle_tag)); 

    printk(KERN_INFO "MODULE: cwnd: %u, oracle_rate: %llu, oracle_flows: %u, pkts: %llu", tp->snd_cwnd, snap->oracle_rate_bps, snap->flows, pkts);
    snap_update_cwnd(sk, pkts);
    snap_set_pacing_rate(sk);
    //   printk(KERN_INFO
    //          "%s: snd_cwnd: %u, rcv_wnd: %u, current_state: %u, pacing_rate: %lu, "
    //          "sampled_rate: %llu, deliverd: %u, interval_us:%lu, packet_out:%u",
    //          prefix, tp->snd_cwnd, tp->rcv_wnd, inet_csk(sk)->icsk_ca_state,
    //          sk->sk_pacing_rate, bw, rs->delivered, rs->interval_us,
    //          tp->packets_out);
}

/**
 * from astraea
 * snap actually does not need this function as we don't always
 * want to reduce CWND in losses.
 */
static u32 snap_undo_cwnd(struct sock *sk) { 
    tcp_sk(sk)->snd_cwnd = 1250000;
    return tcp_sk(sk)->snd_cwnd; 
}

/* save current cwnd for quick ramp up */
static u32 snap_ssthresh(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    // we want RL to take more efficient control
    snap_save_cwnd(sk);
    tp->snd_cwnd = 1250000;
    return max(tp->snd_cwnd, 10U);
}

static void snap_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    // printk(KERN_INFO "[TCP snap] Nothing done in snap CC");
    // struct tcp_sock* tp = tcp_sk(sk);
    // if (tcp_in_cwnd_reduction(sk)) {
    //   // prior_cwnd is the cwnd right before starting loss recovery
    //   if (tp->prior_cwnd > tp->snd_cwnd) tp->snd_cwnd = tp->prior_cwnd;
    // }
}

static void snap_pkts_acked(struct sock *sk, const struct ack_sample *acks)
{
    struct tcp_sock *tp = tcp_sk(sk);
    s32 rtt = max(acks->rtt_us, 0);
    tp->snd_cwnd = 1250000;
    //   printk(KERN_INFO "%s: cwnd: %u, current_state: %u, sampled_rtt: %u", prefix,
    //          tp->snd_cwnd, inet_csk(sk)->icsk_ca_state, rtt);
}

static void snap_ack_event(struct sock *sk, u32 flags) {}

static void snap_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
    if (event == CA_EVENT_LOSS)
    {
        printk(KERN_INFO "%s packet loss: cwnd: %u, current_state: %u", prefix,
               tcp_sk(sk)->snd_cwnd, inet_csk(sk)->icsk_ca_state);
    }
}

static void snap_set_state(struct sock *sk, u8 new_state)
{
    struct snap *snap = inet_csk_ca(sk);

    if (new_state == TCP_CA_Loss)
    {
        snap->prev_ca_state = TCP_CA_Loss;
    }
    else if (new_state == TCP_CA_Recovery)
    {
        printk(KERN_INFO "%s recovery: cwnd: %u, current_state: %u", prefix,
               tcp_sk(sk)->snd_cwnd, inet_csk(sk)->icsk_ca_state);
    }
}

static struct tcp_congestion_ops tcp_snap_ops __read_mostly = {
    .flags = TCP_CONG_NON_RESTRICTED,
    .name = "snap",
    .owner = THIS_MODULE,
    .init = snap_init,
    .cong_control = snap_cong_control,
    .undo_cwnd = snap_undo_cwnd,
    .ssthresh = snap_ssthresh,
    .set_state = snap_set_state,
    .cong_avoid = snap_cong_avoid,
    .pkts_acked = snap_pkts_acked,
    // .in_ack_event = snap_ack_event,
    .cwnd_event = snap_cwnd_event,
};

/* Kernel module section */
static int __init snap_register(void)
{
    BUILD_BUG_ON(sizeof(struct snap) > ICSK_CA_PRIV_SIZE);
    printk(KERN_INFO "KERNEL: [TCP snap] snap init clean tcp congestion control logic\n");
    return tcp_register_congestion_control(&tcp_snap_ops);
}

static void __exit snap_unregister(void)
{
    printk(KERN_INFO "KERNEL: [TCP snap] snap unregistered");
    tcp_unregister_congestion_control(&tcp_snap_ops);
}

module_init(snap_register);
module_exit(snap_unregister);

MODULE_AUTHOR("Xudong Liao <stephenxudong@gmail.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP snap (Clean-version TCP Congestion Control)");