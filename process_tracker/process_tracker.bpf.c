// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2024 Process Tracker */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_ARGS_LEN 96
#define MAX_FILE_LEN 48
#define MAX_ARG_SIZE 16    // 单个参数读取的最大长度
#define MAX_ARGS_COUNT 5   // 最多读取的参数个数

struct proc_info {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];    // 当前进程名
    char pcomm[TASK_COMM_LEN];   // 父进程名
    char filename[MAX_FILE_LEN];
    char args[MAX_ARGS_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct proc_info);
} cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[MAX_ARGS_LEN]);
} combined_args SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char **argv = (const char **)ctx->args[1];
    if (!argv)
        return 0;

    u32 key = 0;
    char *combined = bpf_map_lookup_elem(&combined_args, &key);
    if (!combined)
        return 0;

    __builtin_memset(combined, 0, MAX_ARGS_LEN);

    char arg[MAX_ARG_SIZE] = {0};  
    int offset = 0;

    #pragma unroll
    for (int i = 1; i < MAX_ARGS_COUNT; i++) {
        const char *arg_ptr;
        long ret;

        if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]))
            break;
        if (!arg_ptr)
            break;

        ret = bpf_probe_read_user_str(arg, sizeof(arg), arg_ptr);
        if (ret <= 1)
            continue;
        int arg_len = ret - 1; 

        int remaining = MAX_ARGS_LEN - offset - 1;
        if (remaining <= 0)
            break;
        int copy_len = (arg_len < remaining) ? arg_len : remaining;

        // 拷贝参数到combined（关键修复：用常量循环上限+unroll）
        #pragma unroll
        for (int j = 0; j < MAX_ARG_SIZE; j++) {
            if (j >= copy_len || offset >= MAX_ARGS_LEN - 1)
                break;  // 动态条件放内部，循环上限用常量
            combined[offset++] = arg[j];
        }

        // 加空格分隔参数（仅当还有下一个参数且有剩余空间时）
        if (offset < MAX_ARGS_LEN - 1 && i < MAX_ARGS_COUNT - 1) {
            combined[offset++] = ' ';
        }
    }

    combined[offset >= MAX_ARGS_LEN ? MAX_ARGS_LEN - 1 : offset] = '\0';

    // bpf_printk("argssssssssss:%s",combined);
    struct proc_info info = {0};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    info.pid = pid;
    __builtin_memcpy(info.args, combined, MAX_ARGS_LEN);
    bpf_map_update_elem(&cache, &pid, &info, BPF_ANY);

    return 0; 
}

// SEC("tracepoint/syscalls/sys_enter_execve")
// int trace_execve(struct trace_event_raw_sys_enter *ctx)
SEC("tracepoint/sched/sched_process_exec")
int trace_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *current_task;
    struct task_struct *parent_task;
    struct proc_info *info;
    
    // 分配内存
    info = bpf_ringbuf_reserve(&rb, sizeof(struct proc_info), 0);
    if (!info)
        return 0;
    
    // 获取当前任务结构体
    current_task = (struct task_struct *)bpf_get_current_task();
    if (!current_task) {
        bpf_ringbuf_discard(info, 0);
        return 0;
    }
    
    // 获取当前进程ID
    info->pid = bpf_get_current_pid_tgid() >> 32;
    info->uid = bpf_get_current_uid_gid();
    info->timestamp = bpf_ktime_get_ns();
    
    // 获取当前进程名（正确方法）
    bpf_get_current_comm(info->comm, sizeof(info->comm));
    
    // 获取父进程
    // 不同内核版本可能使用不同字段名，这里尝试多种可能
    parent_task = NULL;
    
    // 尝试获取父进程（使用BPF_CORE_READ）
    BPF_CORE_READ_INTO(&parent_task, current_task, real_parent);
    if (!parent_task) {
        BPF_CORE_READ_INTO(&parent_task, current_task, parent);
    }
    
    if (parent_task) {
        // 获取父进程ID
        BPF_CORE_READ_INTO(&info->ppid, parent_task, pid);
        
        // 获取父进程名
        char parent_comm[TASK_COMM_LEN] = {0};
        if (bpf_core_read(parent_comm, sizeof(parent_comm), &parent_task->comm) >= 0) {
            __builtin_memcpy(info->pcomm, parent_comm, TASK_COMM_LEN);
        } else {
            info->pcomm[0] = '?';
            info->pcomm[1] = '\0';
        }
    } else {
        info->ppid = 0;
        info->pcomm[0] = '?';
        info->pcomm[1] = '\0';
    }

    char filename[MAX_FILE_LEN];
    const char *filename_ptr;
    // 使用 BPF_CORE_READ 宏安全读取
    unsigned int filename_loc = BPF_CORE_READ(ctx, __data_loc_filename);
    // 获取字符串地址
    filename_ptr = (const char *)ctx + (filename_loc & 0xFFFF);
    // 读取字符串
    bpf_probe_read_str(filename, sizeof(filename), filename_ptr);
    __builtin_memcpy(info->filename, filename, MAX_FILE_LEN);

    struct proc_info *temp;
    temp = bpf_map_lookup_elem(&cache, &info->pid);
    if (temp)
    {
        __builtin_memcpy(info->args, temp->args, MAX_ARGS_LEN);
        bpf_map_delete_elem(&cache, &info->pid);
    }

    bpf_ringbuf_submit(info, 0);
    return 0;
}

#if 0
// 另一个钩子：监控进程退出
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct task_struct *current_task;
    struct task_struct *parent_task;
    struct proc_info *info;
    
    info = bpf_ringbuf_reserve(&rb, sizeof(*info), 0);
    if (!info)
        return 0;
    
    current_task = (struct task_struct *)bpf_get_current_task();
    if (!current_task) {
        bpf_ringbuf_discard(info, 0);
        return 0;
    }
    
    // 获取当前进程信息
    info->pid = bpf_get_current_pid_tgid() >> 32;
    info->uid = bpf_get_current_uid_gid();
    info->timestamp = bpf_ktime_get_ns();
    
    // 获取当前进程名
    bpf_get_current_comm(info->comm, sizeof(info->comm));
    
    // 获取父进程信息
    parent_task = NULL;
    BPF_CORE_READ_INTO(&parent_task, current_task, real_parent);
    if (!parent_task) {
        BPF_CORE_READ_INTO(&parent_task, current_task, parent);
    }
    
    if (parent_task) {
        BPF_CORE_READ_INTO(&info->ppid, parent_task, pid);
        
        char parent_comm[TASK_COMM_LEN] = {0};
        if (bpf_core_read(parent_comm, sizeof(parent_comm), &parent_task->comm) >= 0) {
            __builtin_memcpy(info->pcomm, parent_comm, TASK_COMM_LEN);
        } else {
            info->pcomm[0] = '?';
            info->pcomm[1] = '\0';
        }
    } else {
        info->ppid = 0;
        info->pcomm[0] = '?';
        info->pcomm[1] = '\0';
    }
    
    info->from = 0;
    bpf_ringbuf_submit(info, 0);
    return 0;
}
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";
