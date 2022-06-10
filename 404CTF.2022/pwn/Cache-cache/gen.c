#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "defs.ida.h"


int rand_lim(int param_1)
{
  int iVar1;

  do {
    iVar1 = rand();
    iVar1 = iVar1 / (int)(0x7fffffff / (long)(param_1 + 1));
  } while (param_1 < iVar1);
  return iVar1;
}


char picker(char *param_1)

{
int iVar1;
size_t sVar2;

  sVar2 = strlen(param_1);
  iVar1 = rand_lim((int)sVar2 + -1);
  return param_1[iVar1];
}

char msg[32];

int main()
{
 __int64 v20;
int local_130;
int v19;
char local_132;
unsigned int v4, local_128;
char *v3;
unsigned int local_12c;
char *local_118[4];

	local_118[0] = "1234567890";
	local_118[1] = "abcdefghijklmnoqprstuvwyzx";
	local_118[2] = "ABCDEFGHIJKLMNOPQRSTUYWVZX";
	local_118[3] = "!@#$%^&*(){}[]:<>?,./";
	local_128 = 4;

	bzero(msg,32);
	v4 = time(0);
	v20 = 4;
	local_130 = 0x14;
	srandom(v4);

	for (; local_130 != 0; local_130 = local_130 + -1) {
		local_12c = rand_lim((int)local_128 -1);
		local_132 = picker(local_118[local_12c]);
		strncat(msg ,&local_132,1);
	}

	puts(msg);

}
