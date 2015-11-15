#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/interrupt.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Louis Taylor");
MODULE_DESCRIPTION("Do not load this module!!!1111ONE!1!111ONE!!!ELEVEN!! It is 2 spoopy!!!ONE11!!");

/* open syscall with distinct lack of doots */
asmlinkage long (*no_doot_open)(const char __user *, int, umode_t);
asmlinkage unsigned long **sys_call_table;

#define SHARE "/usr/local/share/skeltal/"
static char *doot_png = SHARE "doot.png";
static char *doot_svg = SHARE "doot.svg";
static char *doot_jpg = SHARE "doot.jpg";

static long doots;


static void remove_wp(void)
{
    write_cr0(read_cr0() & (~ 0x10000));
}


static void enable_wp(void)
{
    write_cr0(read_cr0() | 0x10000);
}


asmlinkage long get_fd(const char *name, int flags, umode_t mode)
{
    mm_segment_t old_fs;
    long fd;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    fd = (*no_doot_open)(name, flags, mode);
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


#define LOG_DOOT printk(KERN_INFO "dooting '%s'!\n", filename)

asmlinkage long doot_open(const char __user *filename, int flags, umode_t mode)
{
    if (to_doot_or_not_to_doot()) {
        if (filecmp(filename, ".png") || filecmp(filename, ".PNG")) {
            LOG_DOOT;
            return get_fd(doot_png, flags, mode);
        } else if (filecmp(filename, ".svg") || filecmp(filename, ".SVG")) {
            LOG_DOOT;
            return get_fd(doot_svg, flags, mode);
        } else if (filecmp(filename, ".jpg") || filecmp(filename, ".JPG")) {
            LOG_DOOT;
            return get_fd(doot_jpg, flags, mode);
        }
    }
    return (*no_doot_open)(filename, flags, mode);
}


static unsigned long **find_call_table(void)
{
    unsigned long o;
    unsigned long **call_table_ptr;

    for (o = PAGE_OFFSET; o < ULLONG_MAX; o += sizeof(void *)) {
        call_table_ptr = (unsigned long **) o;
        if (call_table_ptr[__NR_close] == (unsigned long *) sys_close) {
            return call_table_ptr;
        }
    }

    return NULL;
}


irq_handler_t keyboard_handler (int irq, void *dev_id, struct pt_regs *regs)
{
    doots++;

    return (irq_handler_t) IRQ_HANDLED;
}


static int __init doot_init(void)
{
    doots = 0;

    sys_call_table = find_call_table();

    remove_wp();
    no_doot_open = (void *) sys_call_table[__NR_open];
    sys_call_table[__NR_open] = (unsigned long *) doot_open;
    enable_wp();

    request_irq(1, (irq_handler_t) keyboard_handler, IRQF_SHARED, "keyboard_stats_irq", (void *)(keyboard_handler));

    printk(KERN_INFO "oh no! Mr Skeltal is loose inside ur computer!\n");

    return 0;
}


static void __exit doot_cleanup(void)
{
    printk(KERN_INFO "dooted our last doot rip in piece\n");

    remove_wp();
    sys_call_table[__NR_open] = (unsigned long *) no_doot_open;
    enable_wp();

    free_irq(1, (void *)(keyboard_handler));
}


module_init(doot_init);
module_exit(doot_cleanup);
