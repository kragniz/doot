#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Louis Taylor");
MODULE_DESCRIPTION("Do not load this module!!!1111ONE!1!111ONE!!!ELEVEN!! It is 2 spoopy!!!ONE11!!");

/* open syscall with distinct lack of doots */
/* asmlinkage int (*no_doot_open)(const char *, int, umode_t); */
sys_call_ptr_t no_doot_open;
sys_call_ptr_t *syscall_table;

#define SHARE "/usr/local/share/skeltal/"
static char *doot_png = SHARE "doot.png";
static char *doot_svg = SHARE "doot.svg";
static char *doot_jpg = SHARE "doot.jpg";
static char *doot_gif = SHARE "doot_black.gif";

static long doots;


static void remove_wp(void)
{
    write_cr0(read_cr0() & (~ 0x10000));
}


static void enable_wp(void)
{
    write_cr0(read_cr0() | 0x10000);
}


asmlinkage int get_fd(const char *name, struct pt_regs *regs)
{
    mm_segment_t old_fs;
    long fd;
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    regs->si = name;
    fd = (*no_doot_open)(regs);
    set_fs(old_fs);

    return fd;
}


static int filecmp(const char *filename, const char *ext)
{
    int l = strlen(filename);
    return !strcmp(filename + l - 4, ext);
}


static bool to_doot_or_not_to_doot(void) {
    // Always dooting.
    return true;
}


#define LOG_DOOT if (printk_ratelimit()) \
    printk(KERN_INFO "dooting '%s'!\n", name)

asmlinkage long doot_open(const struct pt_regs *regs)
{
	char __user *filename = (char *)regs->si;
    char name[128];
    long res = strncpy_from_user(name, filename, 128);
    if (res <= 0)
	    return res;
    if (strlen(name) >= 3) {
	   if (filecmp(name, ".png") || filecmp(name, ".PNG")) { 
            LOG_DOOT;
            return get_fd(doot_png, regs);
	   }
	} 
    /* if (to_doot_or_not_to_doot()) { */
    /*     if (filecmp(name, ".png") || filecmp(name, ".PNG")) { */
    /*         LOG_DOOT; */
    /*         return get_fd(doot_png, flags, mode); */
    /*     } else if (filecmp(name, ".svg") || filecmp(name, ".SVG")) { */
    /*         LOG_DOOT; */
    /*         return get_fd(doot_svg, flags, mode); */
    /*     } else if (filecmp(name, ".jpg") || filecmp(name, ".JPG")) { */
    /*         LOG_DOOT; */
    /*         return get_fd(doot_jpg, flags, mode); */
    /*     } else if (filecmp(name, ".gif") || filecmp(name, ".GIF")) { */
    /*         LOG_DOOT; */
    /*         return get_fd(doot_gif, flags, mode); */
    /*     } */
    /* } */
    return no_doot_open(regs);
}

/* asmlinkage int doot_open(const char __user *filename, int flags, umode_t mode) */
/* { */
/*     char name[128]; */
/*     long res = strncpy_from_user(name, filename, 128); */
/*     if (res <= 0) */
/* 	    return res; */
/*     if (to_doot_or_not_to_doot()) { */
/*         if (filecmp(name, ".png") || filecmp(name, ".PNG")) { */
/*             LOG_DOOT; */
/*             return get_fd(doot_png, flags, mode); */
/*         } else if (filecmp(name, ".svg") || filecmp(name, ".SVG")) { */
/*             LOG_DOOT; */
/*             return get_fd(doot_svg, flags, mode); */
/*         } else if (filecmp(name, ".jpg") || filecmp(name, ".JPG")) { */
/*             LOG_DOOT; */
/*             return get_fd(doot_jpg, flags, mode); */
/*         } else if (filecmp(name, ".gif") || filecmp(name, ".GIF")) { */
/*             LOG_DOOT; */
/*             return get_fd(doot_gif, flags, mode); */
/*         } */
/*     } */
/*     printk(KERN_INFO "doot"); */
/*     return (*no_doot_open)(filename, flags, mode); */
/* } */


/* static unsigned long **find_call_table(void) */
/* { */
/*     unsigned long o; */
/*     unsigned long **call_table_ptr; */

/*     for (o = PAGE_OFFSET; o < ULLONG_MAX; o += sizeof(void *)) { */
/*         call_table_ptr = (unsigned long **) o; */
/*         if (call_table_ptr[__NR_close] == (unsigned long *) sys_close) { */
/*             eturn call_table_ptr; */
/*         } */
/*     } */

/*     return NULL; */
/* } */


static int __init doot_init(void)
{
    doots = 0;

    syscall_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    printk(KERN_INFO "found at %p\n", syscall_table);

    no_doot_open = syscall_table[__NR_openat];
    remove_wp();
    
    syscall_table[__NR_openat] = doot_open;
    enable_wp();

    printk(KERN_INFO "oh no! Mr Skeltal is loose inside ur computer!\n");

    return 0;
}


static void __exit doot_cleanup(void)
{
    printk(KERN_INFO "dooted our last doot rip in piece\n");

    remove_wp();
    syscall_table[__NR_openat] =  no_doot_open;
    enable_wp();
}


module_init(doot_init);
module_exit(doot_cleanup);
