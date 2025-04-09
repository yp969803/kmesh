// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#ifndef __KMESH_BPF_PROBE_H__
#define __KMESH_BPF_PROBE_H__

#include "tcp_probe.h"
#include "performance_probe.h"

volatile __u32 enable_monitoring = 0;

static inline bool is_monitoring_enable()
{
    return enable_monitoring == 1;
}

static inline void observe_on_pre_connect(struct bpf_sock *sk)
{
    struct tcp_probe_info *storage = NULL;
    if (!sk)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "pre_connect bpf_sk_storage_get failed\n");
        return;
    }

    storage->start_ns = bpf_ktime_get_ns();
    return;
}

static inline void observe_on_connect_established(struct bpf_sock *sk, __u64 sock_cookie, __u8 direction)
{
    if (!is_monitoring_enable()) {
        return;
    }

    struct bpf_tcp_sock *tcp_sock = NULL;
    struct tcp_probe_info *storage = NULL;
    __u64 flags = (direction == OUTBOUND) ? 0 : BPF_LOCAL_STORAGE_GET_F_CREATE;

    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, flags);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "on connect: bpf_sk_storage_get failed\n");
        return;
    }

    // INBOUND scenario

    if (direction == INBOUND)
        storage->start_ns = bpf_ktime_get_ns();
    storage->direction = direction;
    storage->conn_success = true;
    storage->conn_id = sock_cookie;
    record_report_tcp_conn_info(sk, tcp_sock, storage, BPF_TCP_ESTABLISHED);
}

static inline void observe_on_status_change(struct bpf_sock *sk, __u32 state)
{
    if (!is_monitoring_enable()) {
        bpf_printk("on close: monitoring is disabled\n");
        return;
    }

    if (state == BPF_TCP_ESTABLISHED) {
        bpf_printk("on close: returning at bpf_tcp_esta\n");
        return;
    }

    struct bpf_tcp_sock *tcp_sock = NULL;
    struct tcp_probe_info *storage = NULL;
    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        bpf_printk("on close: bpf_sk_storage_get failed\n");
        return;
    }

    refresh_tcp_conn_info_on_state_change(tcp_sock, storage, state);
    if (state == BPF_TCP_CLOSE) {
        bpf_sk_storage_delete(&map_of_sock_storage, sk);
    }
}

static inline void observe_on_retransmit(struct bpf_sock *sk)
{
    if (!is_monitoring_enable()) {
        return;
    }
    struct tcp_probe_info *storage = NULL;
    struct bpf_tcp_sock *tcp_sock = NULL;
    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;

    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        bpf_printk("on retransmit: bpf_sk_storage_get failed\n");

        return;
    }
    refresh_tcp_conn_info_on_retransmit_rtt(tcp_sock, storage);
}

// observe_on_rtt is called when the RTT of a connection changes
static inline void observe_on_rtt(struct bpf_sock *sk)
{
    if (!is_monitoring_enable()) {
        return;
    }

    struct tcp_probe_info *storage = NULL;
    struct bpf_tcp_sock *tcp_sock = NULL;

    if (!sk)
        return;
    tcp_sock = bpf_tcp_sock(sk);
    if (!tcp_sock)
        return;
    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        BPF_LOG(ERR, PROBE, "on rtt: bpf_sk_storage_get failed\n");
        return;
    }
    refresh_tcp_conn_info_on_retransmit_rtt(tcp_sock, storage);
}

static inline void observe_on_data(struct bpf_sock *sk, __u32 size, __u8 direction)
{
    bpf_printk("observing on send");
    struct tcp_probe_info *storage = NULL;
    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        return;
    }
    refresh_tcp_conn_info_on_data(storage, size, direction);
}

static inline void report_after_threshold_tm(struct bpf_sock *sk)
{
    struct tcp_probe_info *storage = NULL;
    storage = bpf_sk_storage_get(&map_of_sock_storage, sk, 0, 0);
    if (!storage) {
        return;
    }

    __u64 now = bpf_ktime_get_ns();
    if ((now - storage->last_report_ns) > LONG_CONN_THRESHOLD_TIME) {
        struct tcp_probe_info *info = bpf_ringbuf_reserve(&map_of_tcp_probe, sizeof(struct tcp_probe_info), 0);
        if (!info) {
            bpf_printk("on report: bpf_ringbuf_reserve failed\n");
            return;
        }

        storage->last_report_ns = now;
        storage->duration = now - storage->start_ns;
        __builtin_memcpy(info, storage, sizeof(struct tcp_probe_info));
        bpf_printk("Tcp time send threshold");

        bpf_printk("conn_id %llu", info->conn_id);
        bpf_printk("send_bytes %u", info->sent_bytes);
        bpf_printk("recv_bytes %u", info->received_bytes);
        bpf_printk("duration %llu", info->duration);
        bpf_printk("srtt_us %u", info->srtt_us);
        bpf_printk("rtt_min %u", info->rtt_min);
        bpf_printk("total_retrans %u", info->total_retrans);
        bpf_printk("lost_out %u", info->lost_out);
        bpf_printk("state %u", info->state);
        bpf_printk("direction %u", info->direction);
        bpf_printk("conn_success %u \n", info->conn_success);
        bpf_ringbuf_submit(info, 0);
    }
}

#endif