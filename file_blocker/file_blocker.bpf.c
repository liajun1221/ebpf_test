#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u64);
    __type(value, u32);
} inode_list SEC(".maps");

#if 0
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32); // pid
    __type(value, u32); // is block
} args_map SEC(".maps");

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(abc, int dfd, const char *filename, struct open_how *how)
{
    struct open_how how_local;
    char fname[256];
    int flags;
    
    if (bpf_probe_read_user_str(fname, sizeof(fname), filename) <= 0) {
        return 0;
    }
    
    if (bpf_probe_read(&how_local, sizeof(how_local), how) < 0) {
        bpf_printk("failed");
        return 0;
    }
    
    int is_target = 1;
    for (int i = 0; i < sizeof(PROTECTED_FILE)-1; i++) {
        if (fname[i] != PROTECTED_FILE[i]) {
            is_target = 0;
            break;
        }
    }
    
    if (!is_target) return 0;

    bpf_printk("file:%s",fname);
    
    // 检查是否是写操作
    flags = how_local.flags;
    if (!(flags & (00000001 | 00000002))) {
        return 0;
    }

    bpf_printk("match and block");
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 block = 1;
    bpf_map_update_elem(&args_map,&pid,&block,BPF_ANY);
    
    return 0;
}

SEC("kretprobe/do_sys_openat2|flags=BPF_F_OVERRIDE_RETURN")
int BPF_KRETPROBE(kretprobe_exit, long ret) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *block = bpf_map_lookup_elem(&args_map, &pid);
    if (!block) return 0;
    
    //bpf_override_return(ctx, -EPERM);
    bpf_map_delete_elem(&args_map, &pid);
    return 0;
}
#endif

#define O_ACCMODE  0x00000003
#define O_RDONLY   0x00000000
#define O_WRONLY   0x00000001
#define O_RDWR     0x00000002
#define O_APPEND   0x00000400
#define O_TRUNC    0x00000200

__attribute__((always_inline, unused)) static bool is_write_op(int flags)
{
    int acc = flags & O_ACCMODE;
    if (acc == O_WRONLY || acc == O_RDWR)
        return true;
    if (flags & (O_TRUNC | O_APPEND))
        return true;
    return false;
}

// SEC("lsm/file_open")
// int BPF_PROG(file_open, struct file *file)
// {
//     int flags;
//     if(bpf_probe_read_kernel(&flags, sizeof(flags), &file->f_flags))
//         return 0;

//     if(!is_write_op(flags))
//         return 0;

//     struct inode *inode = BPF_CORE_READ(file, f_inode);
//     if (!inode) 
//         return 0;

//     u64 ino = BPF_CORE_READ(inode, i_ino);
//     if (ino == (u64)TARGET_INODE)
//     {
//         bpf_printk("inode:%llu, flags:%d", ino, flags);
//         return -EPERM;
//     }

//     return 0;
// }

#define MAY_WRITE 0x00000002
#define MAY_APPEND   0x00000008

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask)
{
    if (!(mask & (MAY_WRITE | MAY_APPEND)))
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) 
        return 0;

    u64 ino = BPF_CORE_READ(inode, i_ino);
    u32 *value = bpf_map_lookup_elem(&inode_list, &ino);
    if (value)
    {
        bpf_printk("inode:%llu, flags:%d", ino, mask);
        return -EPERM;
    }

    //bpf_map_delete_elem(&inode_list, &ino);

    return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(file_rename, struct file *old_file, struct dentry *old_dentry,
             struct file *new_file, struct dentry *new_dentry)
{
    struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
    if (!old_inode)
        return 0;

    u64 old_ino = BPF_CORE_READ(old_inode, i_ino);
    u32 *value = bpf_map_lookup_elem(&inode_list, &old_ino);
    if (value)
    {
        bpf_printk("blocked old inode:%llu", old_ino);
        return -EPERM;
    }

    return 0;
}


char LICENSE[] SEC("license") = "GPL";