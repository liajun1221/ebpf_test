// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "file_blocker.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct file_blocker_bpf *skel;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=== 文件拦截器 ===\n");
    skel = file_blocker_bpf__open();
    if(!skel)
    {
        fprintf(stderr, "打开BPF程序失败\n");
        return 1;
    }

    err = file_blocker_bpf__load(skel);
    if(err)
    {
        fprintf(stderr, "加载BPF程序失败：%d\n", err);
        goto cleanup;
    }

    err = file_blocker_bpf__attach(skel);
    if(err)
    {
        fprintf(stderr, "附加BPF程序失败：%d\n", err);
        goto cleanup;
    }

    while(!exiting)
    {
        sleep(1);
    }


cleanup:
    if (skel) file_blocker_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}