//#include <linux/errno.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

#define MAX_FILENAME_LEN 64
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, u32);
} blocked_processes SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{

    long err;
    char *filename_ptr;
    char filename[MAX_FILENAME_LEN];
    char comm[MAX_FILENAME_LEN] = {0};
    filename_ptr = (char *)ctx->args[0];
    err = bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);
    if (err < 0) {
        return 0;
    }
    //bpf_printk("filename : %s", filename);
    
    // // 提取进程名
    // char comm[TARGET_COMM_LEN] = {0};
    // char *basename = filename;
    // for (int i = 0; filename[i] != '\0'; i++) {
    //     if (filename[i] == '/') {
    //         basename = &filename[i] + 1;
    //     }
    // }

    // // 复制进程名
    // int j = 0;
    // for (int i = 0; i < TARGET_COMM_LEN - 1 && basename[i] != '\0'; i++) {
    //     if (basename[i] == '/' || basename[i] == ' ') {
    //         break;
    //     }
    //     comm[j++] = basename[i];
    // }
    // comm[j] = '\0';

    // 3. 提取进程名（basename）
    int basename_offset = 0;  // 用偏移量替代指针操作，避免栈指针风险
    #pragma unroll
    for (int i = 0; i < MAX_FILENAME_LEN; i++) {
        if (filename[i] == '\0')
            break;
        if (filename[i] == '/') {
            basename_offset = i + 1;
        }
    }

    // 4. 复制进程名（过滤 / 和 空格，限制长度）
    int j = 0;
    #pragma unroll
    for (int i = 0; i < MAX_FILENAME_LEN; i++) {
        // 终止条件：超出缓冲区/源字符串结束/遇到过滤字符
        if (i >= MAX_FILENAME_LEN - 1 ||          // 防止filename越界
            basename_offset + i >= MAX_FILENAME_LEN ||  // 防止basename_offset+i越界
            filename[basename_offset + i] == '\0' ||    // 源字符串结束
            filename[basename_offset + i] == '/' ||     // 过滤/
            filename[basename_offset + i] == ' ') {     // 过滤空格
            break;
        }
        // 确保comm不越界
        if (j >= MAX_FILENAME_LEN - 1)
            break;
        comm[j++] = filename[basename_offset + i];
    }
    comm[j] = '\0';  // 确保字符串终止

    // char comm[16];
    // bpf_get_current_comm(&comm, sizeof(comm));
    
    bpf_printk("comm: %s",comm);

    u32 *block_reason = bpf_map_lookup_elem(&blocked_processes, comm);
    if(block_reason)
    {
        bpf_printk("process %s blocked",comm);
        //bpf_send_signal(9);
        //bpf_override_return(ctx, -EPERM);
    }
    return 0;
}


#define BUF_SIZE 256
#define COMM_MAX_LEN 16

SEC("kprobe/__x64_sys_execve")
int kprobe_sys_execve(struct pt_regs *ctx)
{
    const char *filename;  
    char path_buf[BUF_SIZE] = {0};
    
    #ifdef __x86_64__
    filename = (const char *)PT_REGS_PARM1(ctx);
    #else
    filename = (const char *)PT_REGS_PARM1_CORE(ctx);
    #endif
    
    if (!filename)
        return 0;
    
    long ret = bpf_probe_read_user_str(path_buf, sizeof(path_buf), filename);
    if (ret < 0) {
        // 读取失败，可能是非法指针
        bpf_printk("333");
        return 0;
    }
    
    bpf_printk("execve path: %s", path_buf);
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";