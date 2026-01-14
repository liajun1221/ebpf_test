// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "process_blocker.skel.h"

#define TASK_COMM_LEN 16

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct process_blocker_bpf *skel;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=== 进程拦截器 ===\n");
    skel = process_blocker_bpf__open();
    if(!skel)
    {
        fprintf(stderr, "打开BPF程序失败\n");
        return 1;
    }

    err = process_blocker_bpf__load(skel);
    if(err)
    {
        fprintf(stderr, "加载BPF程序失败：%d\n", err);
        goto cleanup;
    }

    err = process_blocker_bpf__attach(skel);
    if(err)
    {
        fprintf(stderr, "附加BPF程序失败：%d\n", err);
        goto cleanup;
    }

    printf("=== addd ===\n");
    const char* list[]={"nc","whoami",NULL};
    int i =0;
    int value = 1;
    char key[TASK_COMM_LEN] = {0};

    for(;list[i]!=NULL;i++)
    {
        strncpy(key, list[i], sizeof(key)-1);
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.blocked_processes),
                                key,&value,BPF_ANY);
        printf("add proc %s, err:%d\n",key,err);
        if(err)
        {
            fprintf("add proc %s failed: %s\n", list[i],strerror(-err));
        }
    }
    while(!exiting)
    {
        sleep(1);
    }


cleanup:
    if (skel) process_blocker_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}