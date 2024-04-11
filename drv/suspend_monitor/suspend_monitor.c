#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/uaccess.h>

#include <linux/fb.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/syscore_ops.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/mutex.h>


#define LOGI(...)	(pr_info(__VA_ARGS__))

#define LOGE(...)	(pr_err(__VA_ARGS__))

#define MESSAGE_BUFFER_SIZE	5

#define CMD_GET_STATUS	_IOR(0xFF, 123, unsigned char)

enum STATUS_TYPE {
	STATUS_NONE = 0,
	STATUS_SCREEN_ON = 1,
	STATUS_SCREEN_OFF = 2,
	STATUS_SUSPEND = 3,
};

/* 32 bytes in total*/
struct suspend_message_t {
	signed long long kernel_time;			/* 8 bytes */
	struct	timespec64 timeval_utc;			/* 16 bytes	*/
	enum	STATUS_TYPE status_old;			/* 4 bytes */
	enum	STATUS_TYPE status_new;			/* 4 bytes */
};

struct suspend_monitor_t {
	struct	notifier_block fb_notif;
	struct	syscore_ops sys_ops;
	struct	suspend_message_t message[MESSAGE_BUFFER_SIZE];
	int		suspend_message_count;
	int		suspend_message_index_read;
	int		suspend_message_index_write;
	char	write_buff[10];
	int		enable_suspend_monitor;
	wait_queue_head_t	suspend_monitor_queue;
	struct	mutex suspend_monitor_mutex;
};

static struct suspend_monitor_t *monitor;
static char *TAG = "MONITOR";

static ssize_t suspend_monitor_read(struct file *filp, char __user *buf,
				size_t size, loff_t *ppos)
{
	int index;
	size_t message_size = sizeof(struct suspend_message_t);

	LOGI("%s:%s\n", TAG, __func__);

	if (size < message_size) {
		LOGE("%s:read size is smaller than message size!\n", TAG);
		return -EINVAL;
	}

	wait_event_interruptible(monitor->suspend_monitor_queue,
		monitor->suspend_message_count > 0);

	LOGI("%s:read wait event pass\n", TAG);

	mutex_lock(&monitor->suspend_monitor_mutex);

	if (monitor->suspend_message_count > 0) {
		index = monitor->suspend_message_index_read;

		if (copy_to_user(buf, &monitor->message[index], message_size)) {
			LOGE("%s:copy_from_user error!\n", TAG);
			mutex_unlock(&monitor->suspend_monitor_mutex);
			return -EFAULT;
		}

		monitor->suspend_message_index_read++;
		if (monitor->suspend_message_index_read >= MESSAGE_BUFFER_SIZE)
			monitor->suspend_message_index_read = 0;

		monitor->suspend_message_count--;
	}

	mutex_unlock(&monitor->suspend_monitor_mutex);

	LOGI("%s:read count:%d\n", TAG, message_size);

	return message_size;
}

static ssize_t suspend_monitor_write(struct file *filp, const char __user *buf,
				size_t size, loff_t *ppos)
{
	char end_flag = 0x0a, cmd;

	LOGI("%s:%s\n", TAG, __func__);

	/* only support size=2, such as "echo 0 > suspend_monitor" */
	if (size != 2) {
		LOGE("%s:invalid cmd size: size = %d\n", TAG, (int)size);
		return -EINVAL;
	}

	if (copy_from_user(monitor->write_buff, buf, size)) {
		LOGE("%s:copy_from_user error!\n", TAG);
		return -EFAULT;
	}

	if (monitor->write_buff[1] != end_flag) {
		LOGE("%s:invalid cmd: end_flag != 0x0a\n", TAG);
		return -EINVAL;
	}

	cmd = monitor->write_buff[0];

	mutex_lock(&monitor->suspend_monitor_mutex);

	switch (cmd) {
	case '0':
		monitor->enable_suspend_monitor = 0;
		LOGI("%s:disable suspend monitor\n", TAG);
		break;
	case '1':
		monitor->enable_suspend_monitor = 1;
		LOGI("%s:enable suspend monitor\n", TAG);
		break;
	default:
		LOGE("%s:invalid cmd: cmd = %d\n", TAG, cmd);
		mutex_unlock(&monitor->suspend_monitor_mutex);
		return -EINVAL;
	}

	mutex_unlock(&monitor->suspend_monitor_mutex);

	return size;
}

static unsigned int suspend_monitor_poll(struct file *filp,
						struct poll_table_struct *wait)
{
	unsigned int mask = 0;

	LOGI("%s:%s\n", TAG, __func__);

	poll_wait(filp, &monitor->suspend_monitor_queue, wait);

	mutex_lock(&monitor->suspend_monitor_mutex);

	if (monitor->suspend_message_count > 0)
		mask |= POLLIN | POLLRDNORM;

	mutex_unlock(&monitor->suspend_monitor_mutex);

	return mask;
}

static long suspend_monitor_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	void __user *ubuf = (void __user *)arg;
	unsigned char status;

	LOGI("%s:%s\n", TAG, __func__);

	mutex_lock(&monitor->suspend_monitor_mutex);

	switch (cmd) {
	case CMD_GET_STATUS:
		LOGI("%s:ioctl:get enable status\n", TAG);
		if (monitor->enable_suspend_monitor == 0)
			status = 0x00;
		else
			status = 0xff;

		LOGI("%s:ioctl:status=0x%x\n", TAG, status);

		if (copy_to_user(ubuf, &status, sizeof(status))) {
			LOGE("%s:ioctl:copy_to_user fail\n", TAG);
			mutex_unlock(&monitor->suspend_monitor_mutex);
			return -EFAULT;
		}
		break;
	default:
		LOGE("%s:invalid cmd\n", TAG);
		mutex_unlock(&monitor->suspend_monitor_mutex);
		return -ENOTTY;
	}

	mutex_unlock(&monitor->suspend_monitor_mutex);

	return 0;
}

static const struct file_operations suspend_monitor_fops = {
	.owner = THIS_MODULE,
	.read = suspend_monitor_read,
	.write = suspend_monitor_write,
	.poll = suspend_monitor_poll,
	.unlocked_ioctl = suspend_monitor_ioctl,
};

static void write_message(enum STATUS_TYPE status_new)
{
	enum STATUS_TYPE status_old;
	int index;

	LOGI("%s:%s\n", TAG, __func__);

	mutex_lock(&monitor->suspend_monitor_mutex);

	index = monitor->suspend_message_index_write;
	status_old = monitor->message[index].status_new;

	monitor->suspend_message_index_write++;
	if (monitor->suspend_message_index_write >= MESSAGE_BUFFER_SIZE)
		monitor->suspend_message_index_write = 0;

	index = monitor->suspend_message_index_write;

	monitor->message[index].kernel_time = ktime_to_ns(ktime_get());
	ktime_get_ts64(&monitor->message[index].timeval_utc);
	monitor->message[index].status_old = status_old;
	monitor->message[index].status_new = status_new;

	if (monitor->suspend_message_count < MESSAGE_BUFFER_SIZE)
		monitor->suspend_message_count++;

	wake_up_interruptible(&monitor->suspend_monitor_queue);

	mutex_unlock(&monitor->suspend_monitor_mutex);
}

static int fb_notifier_callback(struct notifier_block *self,
			unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	int blank;

	LOGI("%s:%s\n", TAG, __func__);

	mutex_lock(&monitor->suspend_monitor_mutex);

	if (monitor->enable_suspend_monitor == 0) {
		LOGE("%s:suspend monitor is disable\n", TAG);
		mutex_unlock(&monitor->suspend_monitor_mutex);
		return 0;
	}

	mutex_unlock(&monitor->suspend_monitor_mutex);

	/* make sure it is a hardware display blank change occurred */
	if (event != FB_EVENT_BLANK) {
		LOGE("%s:not a FB_EVENT_BLANK event\n", TAG);
		return 0;
	}

	blank = *(int *)evdata->data;

	switch (blank) {
	case FB_BLANK_UNBLANK:
		LOGI("%s:FB_BLANK_UNBLANK\n", TAG);

		write_message(STATUS_SCREEN_ON);

		LOGI("%s:wake up for STATUS_SCREEN_ON\n", TAG);

		break;
	case FB_BLANK_POWERDOWN:
		LOGI("%s:FB_BLANK_POWERDOWN\n", TAG);

		write_message(STATUS_SCREEN_OFF);

		LOGI("%s:wake up for STATUS_SCREEN_OFF\n", TAG);

		break;
	default:
		break;
	}

	return 0;
}

static int suspend_callback(void)
{
	LOGI("%s:%s\n", TAG, __func__);

	mutex_lock(&monitor->suspend_monitor_mutex);

	if (monitor->enable_suspend_monitor == 0) {
		LOGE("%s:suspend monitor is disable\n", TAG);
		mutex_unlock(&monitor->suspend_monitor_mutex);
		return 0;
	}

	mutex_unlock(&monitor->suspend_monitor_mutex);

	write_message(STATUS_SUSPEND);

	LOGI("%s:wake up for STATUS_SUSPEND\n", TAG);

	return 0;
}

static void resume_callback(void)
{
	LOGI("%s:%s\n", TAG, __func__);

	mutex_lock(&monitor->suspend_monitor_mutex);

	if (monitor->enable_suspend_monitor == 0) {
		LOGE("%s:suspend monitor is disable\n", TAG);
		mutex_unlock(&monitor->suspend_monitor_mutex);
		return;
	}

	mutex_unlock(&monitor->suspend_monitor_mutex);

	write_message(STATUS_SCREEN_OFF);

	LOGI("%s:wake up for STATUS_SCREEN_OFF\n", TAG);
}

static int __init suspend_monitor_init(void)
{
	int i, err;

	LOGI("%s:%s\n", TAG, __func__);

	monitor = kzalloc(sizeof(struct suspend_monitor_t), GFP_KERNEL);

	if (!monitor) {
		LOGE("%s:failed to kzalloc\n", TAG);
		return -ENOMEM;
	}

	for (i = 0; i < MESSAGE_BUFFER_SIZE; i++) {
		monitor->message[i].status_old = STATUS_NONE;
		monitor->message[i].status_new = STATUS_NONE;
	}
	monitor->suspend_message_count = 0;
	monitor->suspend_message_index_read = 1;
	monitor->suspend_message_index_write = 0;
	monitor->enable_suspend_monitor = 1;

	proc_create("suspend_monitor", 0644, NULL, &suspend_monitor_fops);

	init_waitqueue_head(&monitor->suspend_monitor_queue);

	mutex_init(&monitor->suspend_monitor_mutex);

	monitor->fb_notif.notifier_call = fb_notifier_callback;
	err = fb_register_client(&monitor->fb_notif);
	if (err)
		LOGE("%s:failed to register fb client, err=%d\n", TAG, err);

	monitor->sys_ops.suspend = suspend_callback;
	monitor->sys_ops.resume = resume_callback;
	register_syscore_ops(&monitor->sys_ops);

	return 0;
}

static void __exit suspend_monitor_exit(void)
{
	int err;

	LOGI("%s:%s\n", TAG, __func__);

	remove_proc_entry("suspend_monitor", NULL);

	err = fb_unregister_client(&monitor->fb_notif);
	if (err)
		LOGE("%s:failed to unregister fb client, err=%d\n", TAG, err);

	unregister_syscore_ops(&monitor->sys_ops);

	kfree(monitor);
}

module_init(suspend_monitor_init);
module_exit(suspend_monitor_exit);

MODULE_AUTHOR("MediaTek");
MODULE_DESCRIPTION("Suspend Monitor");
MODULE_LICENSE("GPL v2");
