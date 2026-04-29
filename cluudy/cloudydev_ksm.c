/*
 * cloudydev_ksm.c — Cloudy Dev 内核内存读写驱动 (built-in)
 *
 * 编译方式 (built-in to kernel):
 *   1. 放入 drivers/cloudydev/ 目录
 *   2. 在同目录添加 Makefile: obj-y += cloudydev_ksm.o
 *   3. 在同目录添加 Kconfig: source "drivers/cloudydev/Kconfig"
 *   4. make menuconfig 启用 CONFIG_CLOUDYDEV=y
 *
 * 安装 (需内核启动后执行一次):
 *   mknod /dev/cloudys c 768 0
 *   chmod 0600 /dev/cloudys
 *   chown root:root /dev/cloudys
 *
 * 注意 (built-in 模式):
 *   - 驱动在内核启动时自动初始化
 *   - 不支持 rmmod (无法卸载 built-in 模块)
 *   - 不自动创建设备节点，需手动 mknod
 *   - 不导出任何符号到 /proc/kallsyms
 *   - 不在 sys 目录创建任何条目
 *   - 主设备号固定为 768
 *
 * 兼容: Android 5.10+ GKI / 非 GKI 内核
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/version.h>
#include <linux/gfp.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/pid.h>

#define DEVICE_NAME     "cloudys"
#define DRIVER_NAME   "cloudy_chrdev"
#define FIXED_MAJOR  768

/* 安全限制 */
#define MAX_COPY_SIZE     (1UL << 20)  /* 单次最多 1MB */
#define MAX_LOOP_ITERS   256           /* 循环上限防卡死 */

/* ioctl 命令 */
#define CLOUDYDEV_DEFAULT       0x800
#define CLOUDYDEV_READ_MEM      0x801
#define CLOUDYDEV_WRITE_MEM    0x802
#define CLOUDYDEV_GET_PID      0x803
#define CLOUDYDEV_GET_MODULE  0x804
#define CLOUDYDEV_GET_MODULE_BSS 0x805

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HonorKings");
MODULE_DESCRIPTION("Cloudy Dev KPM - 内核内存读写驱动");
MODULE_VERSION("1.0.3");

/* ============================================================================
 * 结构体定义（与 5.10_kernel.elf 完全一致）
 * ============================================================================ */

/* 内存读写结构体 */
struct cloudys_copy_mem {
    int32_t   pid;
    uint64_t  addr;
    void __user *buffer;
    uint32_t  size;
};

/* 模块查询结构体 */
struct cloudys_module_query {
    uint64_t base;
    uint32_t pid;
    char     name[64];
};

/* ============================================================================
 * 全局变量 (无 sysfs 条目)
 * ============================================================================ */

static dev_t           cloudydev_devno;
static struct cdev     cloudydev_cdev;
static atomic_t        open_count = ATOMIC_INIT(0);
static atomic_t        device_active = ATOMIC_INIT(0);

/* 初始化阶段标记 */
static int cloudydev_stage = 0;
#define STAGE_CHRDEV_REG  1
#define STAGE_CDEV_ADD    2

/* ============================================================================
 * 辅助函数 (全部 static)
 * ============================================================================ */

static struct task_struct *get_task_by_pid(pid_t pid)
{
    struct pid *p;
    struct task_struct *task;

    p = find_get_pid(pid);
    if (!p)
        return NULL;

    task = get_pid_task(p, PIDTYPE_PID);
    put_pid(p);
    return task;
}

static inline size_t size_in_page(uint64_t addr, size_t sz)
{
    return min(sz, (size_t)(PAGE_SIZE - (addr & ~PAGE_MASK)));
}

/* 虚拟地址转物理地址 */
static uint64_t translate_va_to_pa(struct mm_struct *mm, uint64_t va)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    uint64_t page_addr = 0;

    if (!mm)
        return 0;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || !pgd_present(*pgd))
        return 0;

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || !p4d_present(*p4d))
        return 0;

    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || !pud_present(*pud))
        return 0;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || !pmd_present(*pmd))
        return 0;

    pte = pte_offset_map(pmd, va);
    if (!pte || !pte_present(*pte))
        goto out_unmap;

    page_addr = pte_pfn(*pte) << PAGE_SHIFT;

out_unmap:
    pte_unmap(pte);
    return page_addr | (va & ~PAGE_MASK);
}

/* 写物理地址 */
static int write_phys_addr(uint64_t phys_addr, void *buffer, size_t size)
{
    void *kaddr;
    size_t chunk;
    int ret = 0;

    while (size > 0) {
        chunk = min(size, (size_t)PAGE_SIZE);
        kaddr = ioremap_cache(phys_addr, chunk);
        if (!kaddr) {
            ret = -ENOMEM;
            break;
        }
        memcpy(kaddr, buffer, chunk);
        iounmap(kaddr);
        buffer = (char *)buffer + chunk;
        phys_addr += chunk;
        size -= chunk;
    }

    return ret;
}

/*
 * ============================================================================
 * 核心读写函数
 * ============================================================================
 */

/* 读进程虚拟内存 (带锁保护 + 超时) */
static int read_proc_mem(pid_t pid, uint64_t addr, void __user *uaddr, uint32_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t phys_addr;
    void *kaddr;
    size_t chunk;
    int ret = 0;
    int iter_count = 0;

    /* 大小校验 */
    if (!size || size > MAX_COPY_SIZE)
        return -EINVAL;

    task = get_task_by_pid(pid);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EPERM;
    }

    /* 锁定 mm 以防止 munmap 竞争 */
    if (!down_read_trylock(&mm->mmap_lock)) {
        mmput(mm);
        put_task_struct(task);
        return -EBUSY;  /* 锁被占用则稍后重试 */
    }

    /* 检查目标进程是否已Exit */
    if (task->mm != mm) {
        up_read(&mm->mmap_lock);
        mmput(mm);
        put_task_struct(task);
        return -ESRCH;
    }

    while (size > 0 && iter_count < MAX_LOOP_ITERS) {
        iter_count++;
        chunk = size_in_page(addr, size);

        /* 页表遍历可能失败：VMA 不存在或未映射 */
        phys_addr = translate_va_to_pa(mm, addr);
        if (!phys_addr) {
            ret = -EFAULT;
            break;
        }

        kaddr = ioremap_cache(phys_addr, chunk);
        if (!kaddr) {
            ret = -ENOMEM;
            break;
        }

        /* 使用 access_ok + copy_to_user 更安全，而不是直接解引用用户指针 */
        if (!access_ok(uaddr, chunk) || copy_to_user(uaddr, kaddr, chunk)) {
            iounmap(kaddr);
            ret = -EFAULT;
            break;
        }

        iounmap(kaddr);
        uaddr = (char __user *)uaddr + chunk;
        addr += chunk;
        size -= chunk;
    }

    up_read(&mm->mmap_lock);
    mmput(mm);
    put_task_struct(task);
    return ret;
}

/* 写进程虚拟内存 (带锁保护 + 超时) */
static int write_proc_mem(pid_t pid, uint64_t addr, void __user *uaddr, uint32_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t phys_addr;
    size_t chunk;
    int ret = 0;
    int iter_count = 0;

    /* 大小校验 */
    if (!size || size > MAX_COPY_SIZE)
        return -EINVAL;

    task = get_task_by_pid(pid);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EPERM;
    }

    /* 锁定 mm */
    if (!down_read_trylock(&mm->mmap_lock)) {
        mmput(mm);
        put_task_struct(task);
        return -EBUSY;
    }

    /* 检查目标进程是否已Exit */
    if (task->mm != mm) {
        up_read(&mm->mmap_lock);
        mmput(mm);
        put_task_struct(task);
        return -ESRCH;
    }

    while (size > 0 && iter_count < MAX_LOOP_ITERS) {
        iter_count++;
        chunk = size_in_page(addr, size);

        phys_addr = translate_va_to_pa(mm, addr);
        if (!phys_addr) {
            ret = -EFAULT;
            break;
        }

        /* 先从用户空间拷贝数据到临时缓冲区 */
        {
            void *kbuf = kmalloc(chunk, GFP_KERNEL);
            if (!kbuf) {
                ret = -ENOMEM;
                break;
            }
            if (!access_ok(uaddr, chunk) || copy_from_user(kbuf, uaddr, chunk)) {
                kfree(kbuf);
                ret = -EFAULT;
                break;
            }
            ret = write_phys_addr(phys_addr, kbuf, chunk);
            kfree(kbuf);
            if (ret < 0)
                break;
        }

        uaddr = (char __user *)uaddr + chunk;
        addr += chunk;
        size -= chunk;
    }

    up_read(&mm->mmap_lock);
    mmput(mm);
    put_task_struct(task);
    return ret;
}

/* ============================================================================
 * 模块查询功能
 * ============================================================================ */

static int get_mod_base_by_pid(pid_t pid, const char *mod_name, uint64_t *out_base)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    char buf[256];
    char *path;
    int ret = -ENOENT;

    task = get_task_by_pid(pid);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EPERM;
    }

    down_read(&mm->mmap_lock);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (!vma->vm_file)
            continue;

        path = d_path(&vma->vm_file->f_path, buf, sizeof(buf) - 1);
        if (IS_ERR(path))
            continue;

        if (strstr(path, mod_name)) {
            *out_base = (uint64_t)vma->vm_start;
            ret = 0;
            break;
        }
    }
    up_read(&mm->mmap_lock);

    mmput(mm);
    put_task_struct(task);
    return ret;
}

static int get_mod_base_bss_by_pid(pid_t pid, const char *mod_name, uint64_t *out_base)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    char buf[256];
    char *path;
    int ret = -ENOENT;

    task = get_task_by_pid(pid);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EPERM;
    }

    down_read(&mm->mmap_lock);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (!vma->vm_file)
            continue;

        path = d_path(&vma->vm_file->f_path, buf, sizeof(buf) - 1);
        if (IS_ERR(path))
            continue;

        if (strstr(path, mod_name)) {
            /* 继续查找下一个 anon 段（vm_file == NULL 表示匿名映射） */
            struct vm_area_struct *next = vma->vm_next;
            if (next && (next->vm_flags & VM_READ) && !next->vm_file) {
                *out_base = (uint64_t)next->vm_start;
                ret = 0;
                break;
            }
        }
    }
    up_read(&mm->mmap_lock);

    mmput(mm);
    put_task_struct(task);
    return ret;
}

static int get_pid_by_name(const char *name, pid_t *out_pid)
{
    struct task_struct *task;
    pid_t found_pid = 0;
    char cmd[256];

    rcu_read_lock();
    for_each_process(task) {
        if (task->flags & PF_KTHREAD)
            continue;

        get_task_comm(cmd, task);
        if (strncmp(cmd, name, sizeof(cmd)) == 0) {
            found_pid = task->pid;
            break;
        }
    }
    rcu_read_unlock();

    if (found_pid == 0)
        return -ENOENT;

    *out_pid = found_pid;
    return 0;
}

/* ============================================================================
 * ioctl 分发处理
 * ============================================================================ */

static long dispatch_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct cloudys_copy_mem cm;
    struct cloudys_module_query mq;
    int ret = 0;

    if (cmd == CLOUDYDEV_DEFAULT) {
        return -EINVAL;
    } else if (cmd == CLOUDYDEV_READ_MEM) {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;

        /* 参数校验 */
        if (cm.pid <= 0 || !cm.addr || cm.size == 0 || cm.size > MAX_COPY_SIZE)
            return -EINVAL;
        if (!cm.buffer)
            return -EINVAL;

        ret = read_proc_mem(cm.pid, cm.addr, cm.buffer, cm.size);
        if (ret < 0)
            return ret;
    } else if (cmd == CLOUDYDEV_WRITE_MEM) {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;

        if (cm.pid <= 0 || !cm.addr || cm.size == 0 || cm.size > MAX_COPY_SIZE)
            return -EINVAL;
        if (!cm.buffer)
            return -EINVAL;

        ret = write_proc_mem(cm.pid, cm.addr, cm.buffer, cm.size);
        if (ret < 0)
            return ret;
    } else if (cmd == CLOUDYDEV_GET_PID) {
        if (copy_from_user(&mq, (void __user *)arg, sizeof(mq)))
            return -EFAULT;

        mq.name[sizeof(mq.name) - 1] = '\0';
        if (mq.name[0] == '\0')
            return -EINVAL;
        {
            pid_t pid_out = 0;
            ret = get_pid_by_name(mq.name, &pid_out);
            if (ret < 0)
                return ret;
            mq.base = (uint64_t)pid_out;
        }

        if (copy_to_user((void __user *)arg, &mq, sizeof(mq)))
            return -EFAULT;
    } else if (cmd == CLOUDYDEV_GET_MODULE) {
        if (copy_from_user(&mq, (void __user *)arg, sizeof(mq)))
            return -EFAULT;


        mq.name[sizeof(mq.name) - 1] = '\0';
        if (mq.pid <= 0 || mq.name[0] == '\0')
            return -EINVAL;

        ret = get_mod_base_by_pid(mq.pid, mq.name, &mq.base);
        if (ret < 0)
            return ret;

        if (copy_to_user((void __user *)arg, &mq, sizeof(mq)))
            return -EFAULT;
    } else if (cmd == CLOUDYDEV_GET_MODULE_BSS) {
        if (copy_from_user(&mq, (void __user *)arg, sizeof(mq)))
            return -EFAULT;


        mq.name[sizeof(mq.name) - 1] = '\0';
        if (mq.pid <= 0 || mq.name[0] == '\0')
            return -EINVAL;


        ret = get_mod_base_bss_by_pid(mq.pid, mq.name, &mq.base);
        if (ret < 0)
            return ret;


        if (copy_to_user((void __user *)arg, &mq, sizeof(mq)))
            return -EFAULT;
    } else {
        return -ENOTTY;
    }

    return 0;
}

/* ============================================================================
 * 文件操作
 * ============================================================================ */

static int dispatch_open(struct inode *inode, struct file *filp)
{
    atomic_inc(&open_count);
    printk(KERN_INFO "[cloudydev] open: count=%d\n", atomic_read(&open_count));
    return 0;
}

static int dispatch_close(struct inode *inode, struct file *filp)
{
    atomic_dec(&open_count);
    printk(KERN_INFO "[cloudydev] close: count=%d\n", atomic_read(&open_count));
    return 0;
}

static const struct file_operations dispatch_fops = {
    .owner   = THIS_MODULE,
    .open    = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

/* ============================================================================
 * 模块初始化 / 退出
 * ============================================================================ */

static int __init cloudydev_init(void)
{
    int ret;

    /* 1. 使用固定主设备号 768 */
    cloudydev_devno = MKDEV(FIXED_MAJOR, 0);
    ret = register_chrdev_region(cloudydev_devno, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("[cloudydev] register_chrdev_region failed: %d\n", ret);
        return ret;
    }
    cloudydev_stage |= STAGE_CHRDEV_REG;

    /* 2. 初始化 cdev */
    cdev_init(&cloudydev_cdev, &dispatch_fops);
    cloudydev_cdev.owner = THIS_MODULE;

    /* 3. 添加字符设备 */
    ret = cdev_add(&cloudydev_cdev, cloudydev_devno, 1);
    if (ret < 0) {
        pr_err("[cloudydev] cdev_add failed: %d\n", ret);
        goto err_cdev_add;
    }
    cloudydev_stage |= STAGE_CDEV_ADD;

    /* 不创建 class / device → /sys 下无任何条目 */
    /* 不创建 uevent → 无 uevent 通知用户态 */

    atomic_set(&device_active, 1);
    pr_info("[cloudydev] loaded: /dev/%s, major=%d, minor=0\n",
          DEVICE_NAME, FIXED_MAJOR);
    pr_info("[cloudydev] ioctl: 0x800-0x805\n");

    return 0;

err_cdev_add:
    unregister_chrdev_region(cloudydev_devno, 1);
    return ret;
}

/* built-in 驱动不卸载，module_exit 永不执行 */
static void __exit cloudydev_exit(void)
{
}

module_init(cloudydev_init);
module_exit(cloudydev_exit);