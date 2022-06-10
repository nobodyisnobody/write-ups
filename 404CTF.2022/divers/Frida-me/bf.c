// gcc -O3 bf.c -o bf -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors()
{
//	printf("Error in decrypt...\n");
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


unsigned int vals[192]= {
    0x14be97,0x1a1e98,0x4de99,0x141e9a,0xbfe9b,0x1f1e9c,0x119e9d,0x123e9e,0x1ebe9f,0x18dea0,0x21ea1,0xb7ea2,0x113ea3,0x107ea4,0x173ea5,0x9dea6,
    0xc1ea7,0x14dea8,0x7ea9,0x12beaa,0xa9eab,0xe3eac,0xebead,0x1bfeae,0x151eaf,0x1d5eb0,0xbfeb1,0x19feb2,0xf7eb3,0x13eb4,0x1efeb5,0x177eb6,
    0x181eb7,0x1afeb8,0x18deb9,0x19deba,0x1e1ebb,0x87ebc,0x91ebd,0x1dfebe,0x7bebf,0x71ec0,0x16bec1,0xa3ec2,0xedec3,0xddec4,0x9ec5,0xbdec6,
    0x71ec7,0xbbec8,0x11dec9,0x3eca,0x27ecb,0x73ecc,0x1c5ecd,0x1f3ece,0x119ecf,0x147ed0,0x17ded1,0x8bed2,0x39ed3,0xf1ed4,0x19bed5,0xc3ed6,
    0x73ed7,0x63ed8,0xc7ed9,0x161eda,0x19fedb,0x5edc,0x1b1edd,0x1dede,0x9dedf,0xb3ee0,0x7ee1,0xd7ee2,0x1afee3,0x1e1ee4,0x1c3ee5,0x77ee6,
    0xf3ee7,0x45ee8,0x79ee9,0x3beea,0x1e7eeb,0x1fbeec,0x169eed,0x197eee,0x109eef,0xd1ef0,0x147ef1,0x197ef2,0x8bef3,0x157ef4,0x89ef5,0x14fef6,
    0x1bbef7,0x23ef8,0xc7ef9,0x9fefa,0xcfefb,0xa5efc,0x1efd,0xfefe,0x189eff,0x75f00,0xaff01,0x3ff02,0x19f03,0x129f04,0x195f05,0x1e7f06,
    0x1d1f07,0x1dff08,0xa5f09,0xbff0a,0x67f0b,0x145f0c,0x1cbf0d,0x111f0e,0x21f0f,0x1f7f10,0x13ff11,0x185f12,0x5df13,0x8ff14,0xf7f15,0x195f16,
    0x93f17,0xbdf18,0x19df19,0xc7f1a,0xf1f1b,0xfdf1c,0x1cdf1d,0x1bbf1e,0xc1f1f,0x2bf20,0x1d9f21,0xaff22,0xf1f23,0x18ff24,0x161f25,0x1bdf26,
    0x16bf27,0x7f28,0x145f29,0x19bf2a,0xf9f2b,0xcbf2c,0xf7f2d,0x53f2e,0x53f2f,0x1df30,0x1f1f31,0x159f32,0x193f33,0x9df34,0x193f35,0x119f36,
    0x15df37,0x4bf38,0x15df39,0x14ff3a,0x23f3b,0x1b5f3c,0x1c1f3d,0xa3f3e,0x7f3f,0x16ff40,0x7df41,0x15bf42,0x79f43,0x1f9f44,0xabf45,0x35f46,
    0x1bdf47,0x85f48,0x1eff49,0x9f4a,0x133f4b,0x135f4c,0x21f4d,0x1c1f4e,0x1a5f4f,0x15ff50,0x75f51,0x95f52,0x147f53,0x1e1f54,0xebf55,0x14bf56  };

static void gentable(char *table, unsigned int pin)
{
int i;
	for (i=0; i<192;i++)
		table[i] = (char)(((pin+i) ^ vals[i])>>13);
}

char original_iv[16] = { 0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 00, 00, 00, 00, 00, 00, 00, 00 };
char key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

int main()
{
char table1[192];
char output[192];
char iv[32];
unsigned int pin;

	printf("Buteforcing pin...\n");
	pin = 00001234;
	for(pin=00001234; pin <99991234; pin += 10000)
	{
		gentable(table1, pin);
		memcpy(iv,original_iv,16);
		decrypt(table1, 192, key, iv, output);
		// test if decrypted text start by 'Bien' string.. (in this case we found the correct pin)
		if ((output[0] == 'B') && (output[1] == 'i') && (output[2] == 'e') && (output[3] == 'n'))
		{
			printf("bingo !!  pin found = %d\n", pin);
			puts(output);
			exit(0);
		}
	}
	}
