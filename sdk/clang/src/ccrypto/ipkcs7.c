#include <stdio.h>
#include "iccrypto.h"


SDK_API int Pkcs7_Encrypt(char *certs, char *in, int inlen, char key[16], char *out) {
    printf("*************** Enter: %s", "Pkcs7_Encrypt");
    return 1;
}

SDK_API int Pkcs7_Decrypt(char *in, int inlen, char key[16], char *out) {
    printf("*************** Enter: %s", "Pkcs7_Decrypt");
    return 1;
}