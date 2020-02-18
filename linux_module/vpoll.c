#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Renzo Davoli");
MODULE_DESCRIPTION("vpoll: sythesize event for select/poll/epoll");
MODULE_VERSION("0.01");

#define NAME "vpoll"

#define VPOLL_IOC_MAGIC '^'
#define VPOLL_IO_ADDEVENTS _IO(VPOLL_IOC_MAGIC, 1)
#define VPOLL_IO_DELEVENTS _IO(VPOLL_IOC_MAGIC, 2)
#define VPOLL_IO_SETEVENTS _IO(VPOLL_IOC_MAGIC, 3)
#define EPOLLALLMASK ((__force __poll_t)0x0fffffff)

static int major = -1;
static struct cdev mycdev;
static struct class *vpoll_class = NULL;

struct vpoll_data {
	wait_queue_head_t wqh;
	__poll_t events;
};

static int vpoll_open(struct inode *inode, struct file *file) {
	 struct vpoll_data *vpoll_data;
	 vpoll_data = kmalloc(sizeof(struct vpoll_data), GFP_KERNEL);
	 if (!vpoll_data)
		 return -ENOMEM;
	 vpoll_data->events = 0;
	 init_waitqueue_head(&vpoll_data->wqh);
	 file->private_data = vpoll_data;
	 return 0;
}

static int vpoll_release(struct inode *inode, struct file *file) {
	struct vpoll_data *vpoll_data = file->private_data;

	kfree(vpoll_data);
	return 0;
}


static long vpoll_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	struct vpoll_data *vpoll_data = file->private_data;
	__poll_t events = arg & EPOLLALLMASK;
	long res = 0;

	spin_lock_irq(&vpoll_data->wqh.lock);
	switch(cmd) {
		case VPOLL_IO_ADDEVENTS:
			vpoll_data->events |= events;
			break;
		case VPOLL_IO_DELEVENTS:
			vpoll_data->events &= ~events;
			break;
		case VPOLL_IO_SETEVENTS:
			vpoll_data->events = events;
			break;
		default:
			res = -EINVAL;
	}
	if (res >= 0) {
		res = vpoll_data->events;
	  if (waitqueue_active(&vpoll_data->wqh))
			wake_up_locked_poll(&vpoll_data->wqh, vpoll_data->events);
	}
	spin_unlock_irq(&vpoll_data->wqh.lock);
	return res;
}

static __poll_t vpoll_poll(struct file *file, struct poll_table_struct *wait)
{
	struct vpoll_data *vpoll_data = file->private_data;

	poll_wait(file, &vpoll_data->wqh, wait);

	return READ_ONCE(vpoll_data->events);
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
		.open = vpoll_open,
		.release = vpoll_release,
		.unlocked_ioctl = vpoll_ioctl,
		.poll = vpoll_poll,
};

static char *vpoll_devnode(struct device *dev, umode_t *mode)
{
    if (!mode)
            return NULL;
		*mode = 0666;
    return NULL;
}

static int myinit(void)
{
    int ret;
		struct device *dev;

    if ((ret = alloc_chrdev_region(&major, 0, 1, NAME)) < 0)
        return ret;
		vpoll_class = class_create(THIS_MODULE, NAME);
		if (IS_ERR(vpoll_class)) {
			ret = PTR_ERR(vpoll_class);
			goto error_unregister_chrdev_region;
		}
		vpoll_class->devnode = vpoll_devnode;
    dev = device_create(vpoll_class, NULL, major, NULL, NAME);
		if (IS_ERR(dev)) {
			ret = PTR_ERR(dev);
			goto error_class_destroy;
		}
    cdev_init(&mycdev, &fops);
    if ((ret = cdev_add(&mycdev, major, 1)) < 0)
			goto error_device_destroy;
		printk(KERN_INFO NAME ": loaded\n");
    return 0;
error_device_destroy:
		device_destroy(vpoll_class, major);
error_class_destroy:
    class_destroy(vpoll_class);
error_unregister_chrdev_region:
    unregister_chrdev_region(major, 1);
    return ret;
}

static void myexit(void)
{
		device_destroy(vpoll_class, major);
		cdev_del(&mycdev);
		class_destroy(vpoll_class);
		unregister_chrdev_region(major, 1);
		printk(KERN_INFO NAME ": unloaded\n");
}

module_init(myinit)
module_exit(myexit)
