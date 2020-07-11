#include <asm/syscall.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/kallsyms.h>

/* openat syscall with distinct lack of doots */
static sys_call_ptr_t no_doot_open;
static sys_call_ptr_t *syscall_table;

#define SHARE "/usr/local/share/skeltal/"
static char *doot_png = SHARE "doot.png";
static char *doot_svg = SHARE "doot.svg";
static char *doot_jpg = SHARE "doot.jpg";
static char *doot_gif = SHARE "doot_black.gif";

static long doots;


static inline void mywrite_cr0(unsigned long cr0)
{
	asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

static void enable_wp(void) {
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	mywrite_cr0(cr0);
}

static void disable_wp(void) {
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	mywrite_cr0(cr0);
}

static asmlinkage int get_fd(const char *name, struct pt_regs *regs)
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

#define LOG_DOOT printk_ratelimited(KERN_INFO "dooting '%s'!\n", name)

static asmlinkage long doot_open(const struct pt_regs *regs)
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

int doot_init(void)
{
	doots = 0;

	syscall_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
	printk(KERN_INFO "found at %p\n", syscall_table);

	no_doot_open = syscall_table[__NR_openat];
	disable_wp();

	syscall_table[__NR_openat] = doot_open;
	enable_wp();

	printk(KERN_INFO "oh no! Mr Skeltal is loose inside ur computer!\n");

	return 0;
}

void doot_exit(void)
{
	printk(KERN_INFO "dooted our last doot rip in piece\n");

	disable_wp();
	syscall_table[__NR_openat] =  no_doot_open;
	enable_wp();
}

module_init(doot_init);
module_exit(doot_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LTHM");
MODULE_DESCRIPTION("Do not load this module!!!1111ONE!1!111ONE!!!ELEVEN!!"
		   "It is 2 spoopy!!!ONE11!!");
