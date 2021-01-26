/*
 * Virtio Cryptodev Device
 *
 * Implementation of virtio-cryptodev qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 * Konstantinos Papazafeiropoulos <kpapazaf@cslab.ece.ntua.gr>
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/qdev.h"
#include "hw/virtio/virtio.h"
#include "standard-headers/linux/virtio_ids.h"
#include "hw/virtio/virtio-cryptodev.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

#define OP_CIOCGSESSION 0
#define OP_CIOCFSESSION 1
#define OP_CIOCCRYPT 2

static uint64_t get_features(VirtIODevice *vdev, uint64_t features,
                             Error **errp)
{
    DEBUG_IN();
    return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
    DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
    DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
    DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtQueueElement *elem;
    unsigned int *syscall_type;
    size_t len = 0;
    int fd;

    DEBUG_IN();

    elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
    if (!elem) {
        DEBUG("No item to pop from VQ :(");
        return;
    } 

    DEBUG("I have got an item from VQ :)");

    syscall_type = elem->out_sg[0].iov_base;
    switch (*syscall_type) {
    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_OPEN");

        fd = open("/dev/crypto", O_RDWR);
        if (fd < 0) {
            DEBUG("ERROR: open(/dev/crypto)");
            fd = -1;
        }
        printf("%ld\n", elem->in_sg[0].iov_len);

        len = iov_from_buf(elem->in_sg, elem->in_num, 0, &fd, sizeof(int));
        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_CLOSE");
        fd = * (int*) elem->out_sg[1].iov_base;
        printf("fd: %d\n", fd);

        if (close(fd) < 0) {
            DEBUG("ERROR: close()");
        }
        /* ?? */
        break;

    case VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL:
        DEBUG("VIRTIO_CRYPTODEV_SYSCALL_TYPE_IOCTL");
        /* ?? */
        fd = * (int*) elem->out_sg[1].iov_base;
        printf("fd: %d\n", fd);
        unsigned int cmd = * (unsigned int*) elem->out_sg[2].iov_base;
        printf("IOCTL Type: %d\n", cmd);
        switch (cmd) {
            case OP_CIOCGSESSION: 
                printf("CIOCGSESSION\n");
                struct session_op sess;
                #define KEY_SIZE 24
                memset(&sess, 0, sizeof(sess));
                sess.cipher = CRYPTO_AES_CBC;

                sess.key = (unsigned char*) elem->out_sg[3].iov_base;
                sess.keylen = elem->out_sg[3].iov_len / sizeof(unsigned char);
                printf("keylen: %d\n", sess.keylen);
                // iov_to_buf(elem->out_sg, elem->out_num, 3, sess.key, KEY_SIZE * sizeof(unsigned char));

                int return_value = 0;
                if ((return_value = ioctl(fd, CIOCGSESSION, &sess))) {
                    perror("ioctl(CIOCGSESSION)");
                }

                len += iov_from_buf(elem->in_sg, elem->in_num, 0, &sess, sizeof(sess));
                len += iov_from_buf(elem->in_sg + 1, elem->in_num, 0, &return_value, sizeof(int));
                break;
            case OP_CIOCFSESSION:
                printf("CIOCFSESSION\n");
                unsigned int sess_id = * (unsigned int*) elem->out_sg[3].iov_base;
                if ((return_value = ioctl(fd, CIOCFSESSION, &sess_id))) {
                    perror("ioctl(CIOCFSESSION)");
                }

                len += iov_from_buf(elem->in_sg, elem->in_num, 0, &return_value, sizeof(int));
                break;
            case OP_CIOCCRYPT: 
                printf("CIOCCRYPT\n");
                struct crypt_op* crypt_received = (struct crypt_op*) elem->out_sg[3].iov_base;
                struct crypt_op crypt;

                memcpy(&crypt, crypt_received, sizeof(struct crypt_op));

                crypt.src = (unsigned char*) malloc(sizeof(unsigned char*) * crypt.len);
                memcpy(crypt.src, elem->out_sg[4].iov_base, sizeof(unsigned char*) * crypt.len);

                crypt.iv = (unsigned char*) malloc(sizeof(unsigned char*) * 16);
                memcpy(crypt.iv, elem->out_sg[5].iov_base, sizeof(unsigned char*) * 16);
                
                crypt.dst = (unsigned char*) malloc(sizeof(unsigned char*) * crypt.len);

                if ((return_value = ioctl(fd, CIOCCRYPT, &crypt))) {
                    perror("ioctl(CIOCCRYPT)");
                }

                len += iov_from_buf(elem->in_sg, elem->in_num, 0, crypt.dst, sizeof(unsigned char) * crypt.len);
                len += iov_from_buf(elem->in_sg + 1, elem->in_num, 0, &return_value, sizeof(int));
                
                break;

            default: 
                DEBUG("Unknown ioctl type");
                break; 
        }
        break;

    default:
        DEBUG("Unknown syscall_type");
        break;
    }

    virtqueue_push(vq, elem, len);
    virtio_notify(vdev, vq);
    g_free(elem);
}

static void virtio_cryptodev_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    DEBUG_IN();

    virtio_init(vdev, "virtio-cryptodev", VIRTIO_ID_CRYPTODEV, 0);
    virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_cryptodev_unrealize(DeviceState *dev, Error **errp)
{
    DEBUG_IN();
}

static Property virtio_cryptodev_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_cryptodev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

    DEBUG_IN();
    dc->props = virtio_cryptodev_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_cryptodev_realize;
    k->unrealize = virtio_cryptodev_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_cryptodev_info = {
    .name          = TYPE_VIRTIO_CRYPTODEV,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCryptodev),
    .class_init    = virtio_cryptodev_class_init,
};

static void virtio_cryptodev_register_types(void)
{
    type_register_static(&virtio_cryptodev_info);
}

type_init(virtio_cryptodev_register_types)
