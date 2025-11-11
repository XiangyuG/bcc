#!/usr/bin/env python3
from bcc import BPF
import ctypes

# -----------------------------------------------------------------
# eBPF C code (XDP)
# -----------------------------------------------------------------
bpf_source = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>

// 定义 ringbuf 输出结构体
struct event_t {
    u64 delta;  // 延迟 (ns)
    u32 cpu;    // 当前 CPU
    u32 sport;  // 源端口
};
BPF_RINGBUF_OUTPUT(events, 256);

int xdp_drop_tcp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = (void *)iph + sizeof(*iph);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // 匹配源IP=10.10.1.2
    if (bpf_ntohl(iph->saddr) == 0x0A0A0102) {
        u64 beg = bpf_ktime_get_ns();
        if (bpf_ntohl(iph->saddr) == 0x0A0A0102 && bpf_ntohs(tcph->dest) == 12345 && bpf_ntohs(tcph->source) == 12345) {
            u64 end = bpf_ktime_get_ns();

            struct event_t evt = {};
            evt.delta = end - beg;
            evt.cpu = bpf_get_smp_processor_id();
            evt.sport = bpf_ntohs(tcph->source);
            events.ringbuf_output(&evt, sizeof(evt), 0);

            return XDP_PASS;
        }
        if (bpf_ntohl(iph->saddr) == 0x0A0A0102 && bpf_ntohs(tcph->dest) == 12345 && bpf_ntohs(tcph->source) == 12345) {
            u64 end = bpf_ktime_get_ns();

            struct event_t evt = {};
            evt.delta = end - beg;
            evt.cpu = bpf_get_smp_processor_id();
            evt.sport = bpf_ntohs(tcph->source);
            events.ringbuf_output(&evt, sizeof(evt), 0);

            return XDP_PASS;
        }
        if (bpf_ntohl(iph->saddr) == 0x0A0A0102 && bpf_ntohs(tcph->dest) == 15 && bpf_ntohs(tcph->source) == 12345) {
            u64 end = bpf_ktime_get_ns();

            struct event_t evt = {};
            evt.delta = end - beg;
            evt.cpu = bpf_get_smp_processor_id();
            evt.sport = bpf_ntohs(tcph->source);
            events.ringbuf_output(&evt, sizeof(evt), 0);

            return XDP_PASS;
        }
        if (bpf_ntohl(iph->saddr) == 0x0A0A0102 && bpf_ntohs(tcph->dest) == 888 && bpf_ntohs(tcph->source) == 12345) {
            u64 end = bpf_ktime_get_ns();

            struct event_t evt = {};
            evt.delta = end - beg;
            evt.cpu = bpf_get_smp_processor_id();
            evt.sport = bpf_ntohs(tcph->source);
            events.ringbuf_output(&evt, sizeof(evt), 0);

            return XDP_PASS;
        }
        if (bpf_ntohl(iph->saddr) == 0x0A0A0102 && bpf_ntohs(tcph->dest) == 8111 && bpf_ntohs(tcph->source) == 12345) {
            u64 end = bpf_ktime_get_ns();

            struct event_t evt = {};
            evt.delta = end - beg;
            evt.cpu = bpf_get_smp_processor_id();
            evt.sport = bpf_ntohs(tcph->source);
            events.ringbuf_output(&evt, sizeof(evt), 0);

            return XDP_PASS;
        }
        if (bpf_ntohs(tcph->source) == 12345) {
            u64 end = bpf_ktime_get_ns();

            struct event_t evt = {};
            evt.delta = end - beg;
            evt.cpu = bpf_get_smp_processor_id();
            evt.sport = bpf_ntohs(tcph->source);
            events.ringbuf_output(&evt, sizeof(evt), 0);

            return XDP_PASS;
        }

        u64 end = bpf_ktime_get_ns();
        struct event_t evt = {};
        evt.delta = end - beg;
        evt.cpu = bpf_get_smp_processor_id();
        evt.sport = bpf_ntohs(tcph->source);
        events.ringbuf_output(&evt, sizeof(evt), 0);
        return XDP_PASS;
    }
    return XDP_PASS;
}
"""

# -----------------------------------------------------------------
# Python control logic
# -----------------------------------------------------------------
interface = "enp6s0f1"

b = BPF(text=bpf_source)
fn = b.load_func("xdp_drop_tcp_filter", BPF.XDP)
b.attach_xdp(interface, fn, 0)

print(f"✅ XDP program attached to {interface}")
print("Collecting latency samples via ringbuf (Ctrl+C to stop)\n")

# Python 定义与 eBPF struct 对应的结构体
class Event(ctypes.Structure):
    _fields_ = [
        ("delta", ctypes.c_ulonglong),
        ("cpu", ctypes.c_uint),
        ("sport", ctypes.c_uint),
    ]

# ring buffer 回调函数
def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    print(f"CPU {event.cpu}: src_port={event.sport}, latency={event.delta} ns")

b["events"].open_ring_buffer(handle_event)

try:
    while True:
        b.ring_buffer_poll()
except KeyboardInterrupt:
    print("\nDetaching XDP program...")
    b.remove_xdp(interface, 0)
