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


int main(int argc, char *argv[]) {

	
	f(0x80);

	f(0x7F);
	
	unsigned long a = 0x00000000;
	char b = 0xFF;
	a |= b; // a = 0x8000007F
	a = 0x00000000;
	BYTE c = 0xFF;
	a |= c; // a = 0x000000FF


    printf("88888888888888888\n");
    printf("88888888888888888\n");
    printf("88888888888888888\n");
    printf("88888888888888888\n");
    printf("88888888888888888\n");
    printf("88888888888888888\n");
    printf("88888888888888888\n");
    printf("88888888888888888\n");
    printf("888888888888888886666\n");

    //SM4CTR_Encrypt(NULL, NULL, 0, NULL, NULL, NULL, NULL);
}