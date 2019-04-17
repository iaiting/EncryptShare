#include "IClangAPI.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#define DATA_LEN 32

#define EVP_MAX_KEY_LENGHT 64

SDK_API int SM4_Encrypt(cuchar *key2, cuchar *psBytes, size_t psBytes_len, uchar *eoBytes) {
    //if (eoBytes==NULL) {
    //    return -1;
    //}
    //memcpy(eoBytes, psBytes, psBytes_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[16] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";
    unsigned char iv[16] = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58";
    unsigned char out[1024] = {0};
    int outl, tmp, i;
    unsigned char msg[1024] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    int rv;
    //OpenSSL_add_all_algorithms();
    //EVP_CIPHER_CTX_init(&ctx);
    rv = EVP_EncryptInit_ex(ctx, EVP_sms4_ctr(),NULL, key, NULL);
    if(rv != 1)
    {
            printf("Error");
            return -1;
    }
    outl = 0;
    rv = EVP_EncryptUpdate(ctx, out, &outl, msg, DATA_LEN);
    if(rv != 1)
    {
            printf("Error");
            return -1;
    }
    rv = EVP_EncryptFinal_ex(ctx, out + outl, &tmp);
    outl = outl + tmp;

    printf("----cipher_algo is AES128 cipher_mode is CBC  enc outdata is :-----------\n");
    for(i = 0; i < DATA_LEN; i++)
            printf("%02x ", out[i]);
    printf("\r\n");
    return 0;
}


SDK_API int SM4_Decrypt(cuchar *key, cuchar *eoBytes, size_t eoBytes_len, uchar *moBytes) {
    if (moBytes==NULL) {
        return -1;
    }

    memcpy(moBytes, eoBytes, eoBytes_len);
    return 0;
}
