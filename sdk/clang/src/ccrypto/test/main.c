#include <stdio.h>

#include "../iccrypto.h"

typedef unsigned char BYTE;



void f(unsigned char v)

{

	char c = v;

	unsigned char uc = v;

	unsigned int a = c, b = uc;

	int i = c, j = uc;

	printf("----------------\n");

	printf("%%c: %c, %c\n", c, uc);

	printf("%%X: %X, %X\n", c, uc);

	printf("%%u: %u, %u\n", a, b);

	printf("%%d: %d, %d\n", i, j);

}

static int SM4Ecb_TEST() {
	char *key = "1234567890abcdef";
	char  *in_1 = "1234567890abcdef";
	char  out_1[256] = {0};

	SM4Ecb_Encrypt(in_1, strlen(in_1), key, out_1);

	char  out_2[256] = {0};

	SM4Ecb_Decrypt(out_1, 16, key, out_2);

}
int main(int argc, char *argv[]) {

	SM4Ecb_TEST();

    printf("88888888888888888\n");


    //SM4CTR_Encrypt(NULL, NULL, 0, NULL, NULL, NULL, NULL);
}