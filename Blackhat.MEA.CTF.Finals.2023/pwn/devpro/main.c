#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

size_t g_size = 0;
unsigned char *g_buf = NULL;
FILE *g_dev = NULL;

int getint(const char *msg) {
  int val;
  printf("%s", msg);
  if (scanf("%d%*c", &val) != 1)
    exit(1);
  return val;
}

void open_device() {
  if (g_dev) {
    puts("[-] Device already open");
    return;
  }

  puts("Which device to open?\n"
       "1. /dev/urandom\n"
       "2. /dev/null\n"
       "3. /dev/zero");
  switch (getint("> ")) {
    case 1: g_dev = fopen("/dev/urandom", "rb+"); break;
    case 2: g_dev = fopen("/dev/null", "rb+"); break;
    case 3: g_dev = fopen("/dev/zero", "rb+"); break;
    default: puts("[-] Invalid choice"); return;
  }

  setvbuf(g_dev, NULL, _IONBF, 0);
  puts("[+] OK");
}

void close_device() {
  if (!g_dev) {
    puts("[-] No device opened");
    return;
  }

  fclose(g_dev);
  g_dev = NULL;
  puts("[+] OK");
}

void read_device() {
  if (!g_dev) {
    puts("[-] No device opened");
    return;
  } else if (!g_buf) {
    puts("[-] No buffer allocated");
    return;
  }

  fread(g_buf, 1, g_size, g_dev);
  for (size_t i = 0; i < g_size; i++)
    printf("%02x ", g_buf[i]);
  putchar('\n');
  puts("[+] OK");
}

void write_device() {
  unsigned char c;
  if (!g_dev) {
    puts("[-] No device opened");
    return;
  }

  printf("Data: ");
  for (size_t i = 0; i < g_size; i++) {
    if (scanf("%02hhx", &c) != 1)
      break;
    fwrite(&c, 1, 1, g_dev);
  }
  puts("[+] OK");
}

void alloc_buffer() {
  g_size = getint("Size: ");
  if (g_size > 0x400) {
    puts("[-] Size too big");
    return;
  }

  if (g_buf)
    free(g_buf);
  g_buf = (unsigned char*)malloc(g_size);
  memset(g_buf, 0, g_size);
}

int main() {
  puts("1. Open device\n"
       "2. Allocate buffer\n"
       "3. Read device\n"
       "4. Write device\n"
       "5. Close device");
  while (1) {
    switch (getint("> ")) {
      case 1: open_device(); break;
      case 2: alloc_buffer(); break;
      case 3: read_device(); break;
      case 4: write_device(); break;
      case 5: close_device(); break;
      default:
        return 0;
    }
  }
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}
