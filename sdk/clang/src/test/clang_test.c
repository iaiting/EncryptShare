#include <stdio.h>

int main(int argc, char *argv[]) {


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