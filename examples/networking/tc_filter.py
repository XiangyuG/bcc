#!/usr/bin/python3
from bcc import BPF
from pyroute2 import IPRoute, NetlinkError

text = """
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/if_ether.h>

int tc_pass(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;

    // only process IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return TC_ACT_OK;
    bpf_trace_printk("src=%x dst=%x\\n", ip->saddr, ip->daddr);
    unsigned char *s = (unsigned char *)&ip->saddr;
    unsigned char *d = (unsigned char *)&ip->daddr;

    bpf_trace_printk("SRC=%d.%d\\n", s[0], s[1]);
    bpf_trace_printk("%d.%d\\n", s[2], s[3]);

    bpf_trace_printk("DST=%d.%d\\n", d[0], d[1]);
    bpf_trace_printk("%d.%d\\n", d[2], d[3]);

    return TC_ACT_OK;
}
"""

ipr = IPRoute()
idx = ipr.link_lookup(ifname="cni0")[0]

def safe_tc_del():
    try:
        ipr.tc("del", "ingress", idx, "ffff:")
    except NetlinkError:
        pass  # ignore if not exists

try:
    # 删除旧的 tc hook
    safe_tc_del()

    b = BPF(text=text)
    fn = b.load_func("tc_pass", BPF.SCHED_CLS)

    # 创建 ingress
    ipr.tc("add", "ingress", idx, "ffff:")

    # 挂载 BPF
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)

    print("✔ tc ingress attached on cni0 successfully!")
    print("✔ all packets ACCEPT")

    input("Press ENTER to exit...")

finally:
    print("cleaning up…")
    safe_tc_del()
