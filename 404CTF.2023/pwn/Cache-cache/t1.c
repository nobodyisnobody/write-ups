#include <stdio.h>
#include <stdint.h>
#include <string.h>

int64_t sub_11DD(int a1)
{
int v2;

	do
		v2 = rand() / (0x7FFFFFFF / (a1 + 1));
	while ( v2 > a1 );
	return (unsigned int)v2;
}

int64_t sub_1212(const char *a1)
{
  int v1;

  v1 = strlen(a1);
  return (uint8_t)a1[(int)sub_11DD(v1 - 1)];
}

int main(int argc, char *argv[])
{
unsigned int v3;
int v7,v8;
int64_t v9;
int64_t v10[4];
char src[2];
char dest[32]; 

  v7 = 20;
  memset(dest,0,32);
  if (argc>1)
    v3 = atoi(argv[1]);
  else
    v3 = time(0);
  srand(v3);
  src[0] = 97;
  v10[0] = (int64_t)"1234567890";
  v10[1] = (int64_t)"abcdefghijklmnoqprstuvwyzx";
  v10[2] = (int64_t)"ABCDEFGHIJKLMNOPQRSTUYWVZX";
  v10[3] = (int64_t)"!@#$%^&*(){}[]:<>?,./";
  v9 = 4LL;
  while ( v7 )
  {
    v8 = sub_11DD((unsigned int)(v9 - 1));
    src[0] = sub_1212(v10[v8]);
    strncat(dest, src, 1uLL);
    --v7;
  }
  puts(dest);
}
