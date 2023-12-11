#include <stdio.h>
#include <gmp.h>

void main(int argc, char **argv){
    int intpow = atoi(argv[1]);
    const char *str = argv[2];
    mpz_t a,b,c,d,base;
    mpz_init_set_ui(base,2U); 
    //No way around this. You must initialize every mpz_t type whenever you want to use them.
    mpz_inits(a,b,c,d,NULL);
    mpz_set_ui(a,2U);
    mpz_set_str(c,str,10);
    mpz_pow_ui(b,base,intpow);
    //Just change the numbers I guess.
    mpz_powm(d,a,b,c); //d will give you the answer.
    gmp_printf("%Zd\n",d); //Do you need this o.o
}

