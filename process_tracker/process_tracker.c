// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "process_tracker.skel.h"

#define TASK_COMM_LEN 16
#define MAX_ARGS_LEN 96
#define MAX_FILE_LEN 48

// 与eBPF程序完全匹配的结构体定义
struct proc_info {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char filename[MAX_FILE_LEN];
    char args[MAX_ARGS_LEN];
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_timestamp(__u64 ns)
{
    time_t sec = ns / 1000000000;
    struct tm *tm_info = localtime(&sec);
    
    if (tm_info) {
        char buffer[20];
        strftime(buffer, sizeof(buffer), "%H:%M:%S", tm_info);
        printf("%s.%06ld", buffer, (ns % 1000000000) / 1000);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct proc_info *info = data;
    
    // printf("[");
    // print_timestamp(info->timestamp);
    // printf("] ");
    
    printf("UID:%-5d PID:%-7d PPID:%-7d ", 
           info->uid, info->pid, info->ppid);
    printf("进程: %-10s 父进程: %s  文件名: %s 参数: %s\n", info->comm, info->pcomm, info->filename, info->args);
    
    return 0;
}

int main(int argc, char **argv)
{
    struct process_tracker_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    
    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("=== 进程追踪器 ===\n");
    printf("追踪execve系统调用...\n");
    
    // 打开BPF程序
    skel = process_tracker_bpf__open();
    if (!skel) {
        fprintf(stderr, "打开BPF程序失败\n");
        return 1;
    }
    
    // 加载BPF程序
    err = process_tracker_bpf__load(skel);
    if (err) {
        fprintf(stderr, "加载BPF程序失败: %d\n", err);
        goto cleanup;
    }
    
    // 附加BPF程序
    err = process_tracker_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "附加BPF程序失败: %d\n", err);
        goto cleanup;
    }
    
    // 创建ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "创建ring buffer失败\n");
        err = -1;
        goto cleanup;
    }
    
    printf("eBPF程序加载成功！\n");
    printf("开始追踪进程创建...\n");
    printf("按 Ctrl+C 退出\n\n");
    printf("UID    PID     PPID    进程名             父进程名       文件名       参数\n");
    printf("------------------------------------------------------------------------------\n");
    
    // 主循环
    while (!exiting) {
        err = ring_buffer__poll(rb, 100); // 100ms超时
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "轮询错误: %d\n", err);
            break;
        }
    }
    
    printf("\n停止追踪...\n");
    
cleanup:
    if (rb) ring_buffer__free(rb);
    if (skel) process_tracker_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
