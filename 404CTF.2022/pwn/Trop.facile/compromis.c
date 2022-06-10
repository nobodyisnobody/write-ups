#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
     
int main()
{
  setvbuf(stdout, NULL, _IONBF, 0);
  
  int check=0xdeadbeef;
  int key=0xcafebebe;
  char buf[40];
     
  fgets(buf,49,stdin);
     
  if ((check==0xcafebebe) && (key==0xdeadbeef))
   {
     puts("Bon retour à la Hallebarde, agent!\n");
     system("/bin/bash");
     puts("Déconnexion...\n");
   }
  else
   {
     printf("Cette sécurité est infranchissable, gloire à la Hallebarde!\n");
   }
   return 0;
}

