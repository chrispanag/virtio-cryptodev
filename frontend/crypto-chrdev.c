/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

#define OP_CIOCGSESSION 0
#define OP_CIOCFSESSION 1
#define OP_CIOCCRYPT 2

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	struct scatterlist syscall_type_sg, input_msg_sg, *sgs[2];
	struct virtqueue *vq;
	unsigned int *syscall_type;
	unsigned long flags;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;
	vq = crdev->vq;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	/* ?? */
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[0] = &syscall_type_sg;
	sg_init_one(&input_msg_sg, &crof->host_fd, sizeof(int));
	sgs[1] = &input_msg_sg;

	if (down_interruptible(&crdev->sem))
            return -ERESTARTSYS;
	err = virtqueue_add_sgs(vq, sgs, 1, 1,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	while ((virtqueue_get_buf(vq, &len)) == NULL);

	debug("host fd: %d, len: %d", crof->host_fd, len);

	up(&crdev->sem);
	kfree(syscall_type);
	
	/* If host failed to open() return -ENODEV. */
	/* ?? */
	if (crof->host_fd < 0) {
		ret = -ENODEV;
		goto fail;
	}

	return ret;
fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;

	int err;
	unsigned int len;
	struct scatterlist syscall_type_sg, input_msg_sg, *sgs[2];
	struct virtqueue *vq;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;

	vq = crdev->vq;

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[0] = &syscall_type_sg;
	sg_init_one(&input_msg_sg, &crof->host_fd, sizeof(int));
	sgs[1] = &input_msg_sg;

	if (down_interruptible(&crdev->sem))
            return -ERESTARTSYS;
	err = virtqueue_add_sgs(vq, sgs, 2, 0,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);

	while ((virtqueue_get_buf(vq, &len)) == NULL);

	up(&crdev->sem);
	kfree(syscall_type);
	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, cmd_type_sg, fd_type_sg, *sgs[8];
	struct session_op* sess;
	struct crypt_op* crypt;

	long ret = 0;
	int err, *host_return_val;
	
	unsigned int num_out = 0, num_in = 0, len, *syscall_type, *op, *session_id;

	void __user *key_user_addr, *src_user_addr, *iv_user_addr, *dst_user_addr;

	debug("Entering");

	op = kzalloc(sizeof(unsigned int), GFP_KERNEL);
	*op = -1;

	host_return_val = kzalloc(sizeof(int), GFP_KERNEL);
	*host_return_val = -1;

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&fd_type_sg, &crof->host_fd, sizeof(int));
	sgs[num_out++] = &fd_type_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
		case CIOCGSESSION:
			debug("CIOCGSESSION");

			// TODO: Also something happens here (kmalloc?)

			*op = OP_CIOCGSESSION;

			sg_init_one(&cmd_type_sg, op, sizeof(unsigned int));
			sgs[num_out++] = &cmd_type_sg;

			sess = kzalloc(sizeof(struct session_op), GFP_KERNEL);
			if (copy_from_user(sess, (void __user*) arg, sizeof(struct session_op)) != 0) {
				debug("copy_from_user1");
				return -EFAULT;
			}
			// Key
			key_user_addr = (void __user*) sess->key;
			sess->key = kzalloc(sizeof(unsigned char) * sess->keylen, GFP_KERNEL);
			if (copy_from_user(sess->key, key_user_addr, sizeof(unsigned char) * sess->keylen) != 0) {
				debug("copy_from_user2");
				return -EFAULT;
			}

			sgs[num_out] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out++], sess->key, sizeof(unsigned char) * sess->keylen);

			// Sess op
			sgs[num_out] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out + num_in++], sess, sizeof(struct session_op));

			// Return val
			sgs[num_out + num_in] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out + num_in++], host_return_val, sizeof(int));

			if (down_interruptible(&crdev->sem))
				return -ERESTARTSYS;
			err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
								&syscall_type_sg, GFP_ATOMIC);

			virtqueue_kick(vq);
			while (virtqueue_get_buf(vq, &len) == NULL);

			sess->key = key_user_addr;
			if (copy_to_user((void __user*) arg, sess, sizeof(struct session_op)) != 0) {
				debug("copy_to_user");
				ret = -EFAULT;
				goto out;
			}

			up(&crdev->sem);

			break;

		case CIOCFSESSION:
			debug("CIOCFSESSION");
			*op = OP_CIOCFSESSION;

			session_id = kzalloc(sizeof(unsigned int), GFP_KERNEL);
			if (copy_from_user(session_id, (void __user*) arg, sizeof(unsigned int)) != 0) {
				debug("copy_from_user1");
				return -EFAULT;
			}

			sg_init_one(&cmd_type_sg, op, sizeof(unsigned int));
			sgs[num_out++] = &cmd_type_sg;

			sgs[num_out] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out++], &session_id, sizeof(unsigned int));

			// Return val
			sgs[num_out + num_in] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out + num_in++], host_return_val, sizeof(int));

			if (down_interruptible(&crdev->sem))
				return -ERESTARTSYS;
			err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
								&syscall_type_sg, GFP_ATOMIC);

			virtqueue_kick(vq);
			while (virtqueue_get_buf(vq, &len) == NULL);

			up(&crdev->sem);

			break;

		case CIOCCRYPT:
			debug("CIOCCRYPT");
			*op = OP_CIOCCRYPT;

			// Copy crypt object from user
			crypt = kzalloc(sizeof(struct crypt_op), GFP_KERNEL);
			if (copy_from_user(crypt, (void __user*) arg, sizeof(struct crypt_op)) != 0) {
				debug("copy_from_user1");
				ret = -EFAULT;
				goto out;
			}

			// Copy src from user
			src_user_addr = crypt->src;
			crypt->src = kzalloc(sizeof(unsigned char) * crypt->len, GFP_KERNEL);
			if (copy_from_user(crypt->src, src_user_addr, sizeof(unsigned char) * crypt->len) != 0) {
				debug("copy_from_user1");
				ret = -EFAULT;
				goto out;
			}

			// Copy IV from user
			iv_user_addr = crypt->iv;
			// Len = BLOCK_SIZE 16
			crypt->iv = kzalloc(sizeof(unsigned char) * 16, GFP_KERNEL);
			if (copy_from_user(crypt->iv, iv_user_addr, sizeof(unsigned char) * 16) != 0) {
				debug("copy_from_user1");
				ret = -EFAULT;
				goto out;
			}

			// Allocate crypt->dst for usage
			dst_user_addr = crypt->dst;
			crypt->dst = kzalloc(sizeof(unsigned char) * crypt->len, GFP_KERNEL);

			sg_init_one(&cmd_type_sg, op, sizeof(unsigned int));
			sgs[num_out++] = &cmd_type_sg;

			sgs[num_out] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out++], crypt, sizeof(*crypt));

			// SG ELEMENT for src
			sgs[num_out] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out++], crypt->src, sizeof(unsigned char) * crypt->len);

			// SG ELEMENT for IV
			// Len = BLOCK_SIZE 16
			sgs[num_out] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out++], crypt->iv, sizeof(unsigned char) * 16);

			// SG ELEMENT for dst
			sgs[num_out] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out + num_in++], crypt->dst, sizeof(unsigned char) * crypt->len);

			// Return val
			sgs[num_out + num_in] = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
			sg_init_one(sgs[num_out + num_in++], host_return_val, sizeof(int));


			if (down_interruptible(&crdev->sem))
				return -ERESTARTSYS;
			err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
								&syscall_type_sg, GFP_ATOMIC);

			virtqueue_kick(vq);
			while (virtqueue_get_buf(vq, &len) == NULL);

			// TODO: HERE Crashes because crypt->dst is invalid (possibly)
			if (copy_to_user(dst_user_addr, crypt->dst, sizeof(unsigned char) * crypt->len) != 0) {
				debug("copy_to_user");
				ret = -EFAULT;
				goto out;
			}

			up(&crdev->sem);

			break;

		default:
			debug("Unsupported ioctl command");

			break;
	}

	ret = (long) *host_return_val;

	debug("Done");
	
	kfree(syscall_type);
	debug("Leaving");

	return ret;
out:
	debug("Leaving with error");
	up(&crdev->sem);

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
