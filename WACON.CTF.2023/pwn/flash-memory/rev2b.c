#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>

#define NUM_THREADS 16

// Structure to hold thread arguments
struct ThreadArgs {
    uint64_t value;
    int offset;
};

unsigned long long crc_32_1420(unsigned long long dataStart, unsigned long long dataLength)
{
  unsigned int crc32Polynomial; // ecx
  int bitIndex; // [rsp+0h] [rbp-24h]
  unsigned long long byteIndex; // [rsp+4h] [rbp-20h]
  unsigned int checksum; // [rsp+10h] [rbp-14h]

  checksum = -1;
  for ( byteIndex = 0LL; byteIndex < dataLength; ++byteIndex )
  {
    checksum ^= *(unsigned char *)(dataStart + byteIndex);
    for ( bitIndex = 0; bitIndex < 8; ++bitIndex )
    {
      crc32Polynomial = 0;
      if ( (checksum & 1) != 0 )
        crc32Polynomial = 0xEDB88320;
      checksum = crc32Polynomial ^ (checksum >> 1);
    }
  }
  return ~checksum;
}


// Function executed by each thread
void *threadFunction(void *arg) {
unsigned long long o, real;

	struct ThreadArgs *args = (struct ThreadArgs *)arg;
	uint64_t value = args->value;
	int offset = args->offset;

	for (o = 0x550000000+offset; o<0x570000000; o+=NUM_THREADS)
	{
                real = o;
                if (crc_32_1420(&real, strlen(&real)) == value)
                {
                        printf("o found = 0x%llx\n", real);
                        break;

                }
        }

    // Thread has finished, return
    pthread_exit(real);
}

int main(int argc, char *argv[]) {
unsigned long long val;
pthread_t threads[NUM_THREADS];
struct ThreadArgs threadArgs[NUM_THREADS];


	if (argc<2)
	{
		printf("%s <val to bruteforce>\n", argv[0]);
		exit(0);
	}
	val = strtoull(argv[1], NULL,16);

    // Create and launch threads
    for (int i = 0; i < NUM_THREADS; i++) {
        threadArgs[i].value = val; // 64-bit value
        threadArgs[i].offset = i;

        int result = pthread_create(&threads[i], NULL, threadFunction, &threadArgs[i]);
        if (result != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    // Wait for any one thread to return
    int index;
    void *thread_result;
    pthread_join(threads[index], &thread_result);

    uint64_t returned_value = (uint64_t)thread_result;
//    printf("Thread %d has returned with value: %p\n", index, returned_value);

    // Optionally, you can wait for the remaining threads to finish using pthread_join
    exit(0);
}
