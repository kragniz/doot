#include <linux/module.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <asm/syscall.h>

#if defined(CONFIG_X86)
typedef sys_call_ptr_t arch_syscall_ptr_t;
#elif defined(CONFIG_ARM64)
typedef syscall_fn_t arch_syscall_ptr_t;
#else
#error "Unsupported architecture for doot :("
#endif


/* openat syscall with distinct lack of doots */
static arch_syscall_ptr_t no_doot_open;

/* address of the syscall table */
static arch_syscall_ptr_t *syscall_table;

#define SHARE "/usr/local/share/skeltal/"
static char *doot_png = SHARE "doot.png";
static char *doot_svg = SHARE "doot.svg";
static char *doot_jpg = SHARE "doot.jpg";
static char *doot_gif = SHARE "doot_black.gif";

static long doots;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func;

/*
 * HACK: write_cr0 triggers a WARN in linux 5.X+
 * Let's inline assembly to do the job instead.
 */

#if defined(CONFIG_X86)
inline void my_write_cr0(unsigned long cr0)
{
	asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
}
#elif defined(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
#endif

static void enable_wp(void)
{
#if defined(CONFIG_X86)
	unsigned long cr0;

	cr0 = read_cr0();
	set_bit(16, &cr0);
	my_write_cr0(cr0);
#elif defined(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol((unsigned long)syscall_table), (unsigned long)syscall_table, __NR_syscalls * sizeof(*syscall_table), PAGE_KERNEL_RO);
#endif
}

static void disable_wp(void)
{
#if defined(CONFIG_X86)
	unsigned long cr0;

	cr0 = read_cr0();
	clear_bit(16, &cr0);
	my_write_cr0(cr0);
#elif defined(CONFIG_ARM64)
	update_mapping_prot(__pa_symbol((unsigned long)syscall_table), (unsigned long)syscall_table, __NR_syscalls * sizeof(*syscall_table), PAGE_KERNEL);
#endif
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
				break;
			}

			/* overwrite with doot_path */
			if (copy_to_user(addr, doot_path, doot_size)) {
				pr_err("couldn't copy to user addr %p\n", addr);
				break;
			}

			/* now we can call openat() with our "userspace" path to the doot file! */
#if defined(CONFIG_X86)
			non_const_regs->si = (unsigned long) addr;
#elif defined(CONFIG_ARM64)
			non_const_regs->regs[1] = (unsigned long) addr;
#endif
			fd = (*no_doot_open)(non_const_regs);

			/* restore what was previously there */
			if (copy_to_user(addr, backup, doot_size)) {
				pr_err("couldn't copy to user addr %p\n", addr);
				break;
			}

			break;
		}
		vma = vma->vm_next;
	}
	mmput(mm);
	up_read(&mm->mmap_lock);

	kfree(backup);

	/* couldn't find a suitable virtual memory area.. can't doot :( */
	if (fd == -1)
		fd = (*no_doot_open)(regs);

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

#if defined(CONFIG_X86)
	filename = (char *) regs->si;
#elif defined(CONFIG_ARM64)
	filename = (char *) regs->regs[1];
#endif

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

#ifdef CONFIG_ARM64
/*
 * run over the memory till find the sys call talbe
 * doing so, by searching the sys call close.
 *
 * stolen from:
 * https://infosecwriteups.com/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c
 */
asmlinkage long (*sys_close)(unsigned int fd);
static unsigned long * obtain_syscall_table_bf(void)
{
  unsigned long *syscall_table;
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}
#endif

int doot_init(void)
{

	struct kprobe kp;

	/* find the address of kallsyms_lookup_name */
	memset(&kp, 0, sizeof(struct kprobe));
	kp.symbol_name = "kallsyms_lookup_name";
	register_kprobe(&kp);
	kallsyms_lookup_name_func = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	/* use it to find the address of the syscall table */
#if defined(CONFIG_X86)
	syscall_table = (arch_syscall_ptr_t *) kallsyms_lookup_name_func("sys_call_table");
#elif defined(CONFIG_ARM64)
	update_mapping_prot = (void *)kallsyms_lookup_name_func("update_mapping_prot");
	if (update_mapping_prot == NULL) {
		pr_info("failed to lookup update_mapping_prot\n");
		return -ENOENT;
	}
	sys_close = (void *)kallsyms_lookup_name_func("__arm64_sys_close");
	if (sys_close == NULL) {
		pr_info("failed to lookup __arm64_sys_close\n");
		return -ENOENT;
	}
	syscall_table = (arch_syscall_ptr_t *) obtain_syscall_table_bf();
#endif
	pr_info("found syscall table at 0x%lx\n", (unsigned long)syscall_table);
	if (syscall_table == NULL)
		return -ENOENT;

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
