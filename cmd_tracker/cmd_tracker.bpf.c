#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*只能获取到/bin/bash作为shell的执行命令，如果是其他的shell暂时获取不到。
并且如果/bin/bash文件位置变了也会失效，这里SEC是硬编码的绝对路径*/

SEC("uretprobe//bin/bash:readline")
// int uretprobe_bash_readline(struct pt_regs *ctx)//第一次执行的命令总是获取不到
int BPF_KRETPROBE(uretprobe_bash_readline, char *ret)
{
    if (!ret) return 0;

    char cmd[256];
    // 从用户空间读取返回的命令字符串
    //if (bpf_probe_read_user_str(cmd, sizeof(cmd), (void *)PT_REGS_RC(ctx)) <= 0 )
    if (bpf_probe_read_user_str(cmd, sizeof(cmd), ret) <= 0) 
    {
        return 0;
    }

    bpf_printk("BASH CMD: %s", cmd);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
