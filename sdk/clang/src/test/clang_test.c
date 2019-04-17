#include <stdio.h>

/******************************************************************************/
static void SM2_Genkey2hex_TEST() {
	char pubkeyhex[1024] = {0};
	char privkeyhex[1024] = {0};
	SM2_Genkey2hex(pubkeyhex, privkeyhex);
}

int main(int argc, char *argv[]) {
	SM2_Genkey2hex_TEST();


	return -1;

	SM2_Encrypt(NULL, 1, NULL, 10, NULL, NULL);

    printf("**************************t101:\012");
	printf("**************************t101:\012");

	printf("**************************t101:\012");
	printf("**************************t101:\012");

	printf("**************************t101:\012");
	printf("**************************t101:\012");


	unsigned char eoBytes[16] = { 0 };
	int rv = SM4_Encrypt("123", "abc", 3, eoBytes);

    return 0;
}