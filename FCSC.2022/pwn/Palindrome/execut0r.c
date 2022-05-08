//gcc -Wall -Wextra -z execstack execut0r.c -o execut0r
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

int main (int argc, char **argv) {
	if (argc != 2) {
		printf("Usage: %s <shellcode_file>\n", argv[0]);
		exit(1);
	}
	uint8_t sc[1024];
	FILE *fp = fopen(argv[1], "r");
	fread(sc, sizeof(sc), 1, fp);
	fclose(fp);
	((void (*) (void)) sc) ();
	return EXIT_SUCCESS;
}
