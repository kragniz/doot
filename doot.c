#include <linux/module.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/sched/mm.h>
#include <asm/uaccess.h>

/* openat syscall with distinct lack of doots */
static sys_call_ptr_t no_doot_open;

/* address of the syscall table */
static sys_call_ptr_t *syscall_table;

#define SHARE "/usr/local/share/skeltal/"
static char *doot_png = SHARE "doot.png";
static char *doot_svg = SHARE "doot.svg";
static char *doot_jpg = SHARE "doot.jpg";
static char *doot_gif = SHARE "doot_black.gif";

static long doots;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func = NULL;

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

static asmlinkage long get_fd(const char *doot_path, const struct pt_regs *regs)
{
	int fd;
	void __user *addr;
	void *backup;
	int doot_size;
	struct pt_regs *non_const_regs;
	struct vm_area_struct *vma;
	struct mm_struct *mm;

	fd = -1;

	doot_size = strlen(doot_path) + 1;
	backup = kmalloc(doot_size, GFP_KERNEL);

	/* HACK: cast away constness */
	non_const_regs = (struct pt_regs *) regs;

	/* iterate over the virtual memory areas of the current process */
	mm = current->mm;
	mmget(mm);
	down_read(&mm->mmap_lock);
	vma = mm->mmap;
	while (vma) {
		/* check if the area is readable and writable */
		if ((vma->vm_flags & (VM_READ | VM_WRITE)) == (VM_READ | VM_WRITE)) {

			/* is there enough space in this area to write the doot_path? */
			if ((vma->vm_end - vma->vm_start) < doot_size) {
				vma = vma->vm_next;
				continue;
			}

			addr = (void __user *) vma->vm_start;

			/* let's backup what's currently at the address */
			if (copy_from_user(backup, addr, doot_size)) {
				pr_err("Couldn't copy from user addr %p\n", addr);
				BUG();
			}

			/* overwrite with doot_path */
			if (copy_to_user(addr, doot_path, doot_size)) {
				pr_err("couldn't copy to user addr %p\n", addr);
				BUG();
			}

			/* now we can call openat() with our "userspace" path to the doot file! */
			non_const_regs->si = (unsigned long) addr;
			fd = (*no_doot_open)(non_const_regs);

			/* restore what was previously there */
			if (copy_to_user(addr, backup, doot_size)) {
				pr_err("couldn't copy to user addr %p\n", addr);
				BUG();
			}

			break;
		}
		vma = vma->vm_next;
	}
	mmput(mm);
	up_read(&mm->mmap_lock);

	kfree(backup);

	/* couldn't find a suitable virtual memory area.. can't doot :( */
	if (fd == -1) {
		fd = (*no_doot_open)(regs);
	}

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

#define LOG_DOOT pr_info("dooting '%s'!\n", name)

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

	struct kprobe kp;

	/* find the address of kallsyms_lookup_name */
	kp.symbol_name = "kallsyms_lookup_name";
	register_kprobe(&kp);
	kallsyms_lookup_name_func = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	/* use it to find the address of the syscall table */
	syscall_table = (sys_call_ptr_t *) kallsyms_lookup_name_func("sys_call_table");
	pr_info("found syscall table at %p\n", syscall_table);

	/* backup the real openat() syscall so we can also use it and restore it later */
	no_doot_open = syscall_table[__NR_openat];

	/* disable write protection on the syscall table and write in our doot implementation */
	disable_wp();
	syscall_table[__NR_openat] = doot_open;
	enable_wp();

	pr_info("oh no! Mr Skeltal is loose inside ur computer!\n");
	doots = 0;

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
