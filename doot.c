#include <asm/syscall.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/printk.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/kprobes.h>

/* openat syscall with distinct lack of doots */
static sys_call_ptr_t no_doot_open;
static sys_call_ptr_t *syscall_table;

#define SHARE "/usr/local/share/skeltal/"
static char *doot_png = SHARE "doot.png";
static char *doot_svg = SHARE "doot.svg";
static char *doot_jpg = SHARE "doot.jpg";
static char *doot_gif = SHARE "doot_black.gif";

static long doots;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func = NULL;
void (*set_fs_func) (mm_segment_t seg) = NULL;
mm_segment_t (*get_fs_func) (void) = NULL;

#define KERNEL_DS	(mm_segment_t) { -0UL }

static void get_functions(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};

	register_kprobe(&kp);
	kallsyms_lookup_name_func = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	set_fs_func = kallsyms_lookup_name_func("set_fs");
	get_fs_func = kallsyms_lookup_name_func("get_fs");
}

/*
 * HACK: write_cr0 triggers a WARN in linux 5.X+
 * Let's inline assembly to do the job instead.
 */

inline void my_write_cr0(unsigned long cr0) {
  asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
}

static void enable_wp(void)
{
	unsigned long cr0;

	cr0 = read_cr0();
	set_bit(16, &cr0);
	my_write_cr0(cr0);
}

static void disable_wp(void)
{
	unsigned long cr0;

	cr0 = read_cr0();
	clear_bit(16, &cr0);
	my_write_cr0(cr0);
}

static asmlinkage long get_fd(const char *name, const struct pt_regs *regs)
{
	mm_segment_t old_fs;
	long fd;
	struct pt_regs *non_const_regs;

	/* HACK: cast away constness */
	non_const_regs = (struct pt_regs *) regs;

	old_fs = get_fs_func();
	set_fs_func(KERNEL_DS);

	/* Use real openat syscall to get the fd of our doot file */
	non_const_regs->si = (unsigned long) name;
	fd = (*no_doot_open)(non_const_regs);

	set_fs_func(old_fs);

	return fd;
}

static int extcmp(const char *filename, const char *ext)
{
	size_t l;

	l = strlen(filename);
	return !strcmp(filename + l - 4, ext);
}


static int to_doot_or_not_to_doot(void)
{
	/* Always dooting. */
	return true;
}

#define LOG_DOOT printk_ratelimited(KERN_INFO "dooting '%s'!\n", name)

static asmlinkage long doot_open(const struct pt_regs *regs)
{
	char __user *filename;
	char *name;
	size_t len;

	filename = (char *) regs->si;

	/* We shouldn't directly use filename */
	name = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	len  = strncpy_from_user(name, filename, PATH_MAX);

	/* Check strncpy_from_user() return value */
	if (len <= 0) {
		kfree(name);
		return len;
	}

	/* Check if dootable and long enough to have an extension */
	if (to_doot_or_not_to_doot() && strlen(name) >= 3) {
		if (extcmp(name, ".png") || extcmp(name, ".PNG")) {
			LOG_DOOT;
			doots++;
			kfree(name);
			return get_fd(doot_png, regs);
		} else if (extcmp(name, ".svg") || extcmp(name, ".SVG")) {
			LOG_DOOT;
			doots++;
			kfree(name);
			return get_fd(doot_svg, regs);
		} else if (extcmp(name, ".jpg") || extcmp(name, ".JPG")) {
			LOG_DOOT;
			doots++;
			kfree(name);
			return get_fd(doot_jpg, regs);
		} else if (extcmp(name, ".gif") || extcmp(name, ".GIF")) {
			LOG_DOOT;
			doots++;
			kfree(name);
			return get_fd(doot_gif, regs);
		}
	}

	kfree(name);
	return no_doot_open(regs);
}

int doot_init(void)
{
	doots = 0;

	get_functions();

	syscall_table = (sys_call_ptr_t *) kallsyms_lookup_name_func(
							"sys_call_table");
	pr_info("found syscall table at %p\n", syscall_table);

	/* Let's store the real openat so we can use it, too */
	no_doot_open = syscall_table[__NR_openat];

	disable_wp();
	syscall_table[__NR_openat] = doot_open;
	enable_wp();

	pr_info("oh no! Mr Skeltal is loose inside ur computer!\n");

	return 0;
}

void doot_exit(void)
{
	pr_info("dooted our last doot rip in piece\n");
	pr_info("total doots: %ld\n", doots);

	disable_wp();
	syscall_table[__NR_openat] = no_doot_open;
	enable_wp();
}

module_init(doot_init);
module_exit(doot_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LTHM");
MODULE_DESCRIPTION("Do not load this module!!!1111ONE!1!111ONE!!!ELEVEN!! It is 2 spoopy!!!ONE11!!");
