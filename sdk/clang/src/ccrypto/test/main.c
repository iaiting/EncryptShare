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


static void hex_to(char* dst, const void* src, size_t len)
{
    const unsigned char *p = src;
    while (len--)
    {
        // *dst++ = hex_to0(*p >> 4);
        // *dst++ = hex_to0(*p & 0x0F);

        *dst++ = "0123456789abcdef"[*p >> 4];
        *dst++ = "0123456789abcdef"[*p & 0x0F];
        p++;
    }
}



static inline int hex_from0(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;

    // assert(0);
    return 0;
}

static void hex_from(void* dst, const char* src, size_t len)
{
    unsigned char *p = dst;
    while (len--)
    {
        *p++ = (hex_from0(src[0]) << 4) | hex_from0(src[1]);
        src += 2;
    }
}


static void SM4Ecb_TEST() {
	char *key = "1234567890abcdef";
	char  *in_1 = "1234567890abcdef123";
	char  out_1[256] = {0};

	SM4Ecb_Encrypt(in_1, strlen(in_1), key, out_1);

	char  out_2[256] = {0};

	SM4Ecb_Decrypt(out_1, 16, key, out_2);

}
//


static void EVP_SM4CTR_TEST(void) {
	unsigned char key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    // char ive[16] = { 0xff, 0x01 };
    //char ive[16] = { 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff};

    unsigned long int icounter = 0;
    // char ive[16];
    // counter2buffer(icounter, ive);

    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

	unsigned char *plaintext = (unsigned char *)"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd";
    int plaintext_len =  strlen(plaintext);

    ciphertext_len = SM4CTR_Encrypt(plaintext, plaintext_len, key, icounter, ciphertext);

	decryptedtext_len = SM4CTR_Decrypt(ciphertext, ciphertext_len, key, icounter, decryptedtext);

    return ;

}



void Pkcs7_TEST() {

	Pkcs7_Encrypt(NULL, NULL, 16, NULL, NULL);
	return;

}


int main(int argc, char *argv[]) {
	
	Pkcs7_TEST();

    EVP_SM4CTR_TEST();

	//EVP_SM4Ecb_TEST();


	char dst[256] = {0};
	hex_to(dst, "3031ff", 6);

	char dst2[256] = {0};
	hex_from(dst, "3031ff", 6);
	// hex_from(void* dst, const char* src, size_t len)

	SM4Ecb_TEST();

    printf("88888888888888888\n");


    //SM4CTR_Encrypt(NULL, NULL, 0, NULL, NULL, NULL, NULL);
	return 0;
}