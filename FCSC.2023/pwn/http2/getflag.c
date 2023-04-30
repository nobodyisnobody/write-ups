#include <stdio.h>
#include <stdlib.h>

#define FLAG "./flag.txt"

int main(void)
{
	char flag[0x100];

	FILE *fp = fopen(FLAG, "r");
	if(NULL == fp) {
		perror("fopen");
		return EXIT_FAILURE;
	}

	if(NULL == fgets(flag, sizeof(flag), fp)) {
		perror("fgets");
		return EXIT_FAILURE;
	}

	fclose(fp);
	puts(flag);

	return EXIT_SUCCESS;
}
