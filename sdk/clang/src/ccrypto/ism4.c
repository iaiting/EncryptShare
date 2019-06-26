#include <stdio.h>
#include "iccrypto.h"
#include "openssl/sms4.h"
#include <openssl/evp.h>


/*
 * 判断机器是否是小段模式
 */

int is_litttle_endian() {
	int i = 1;
	return *(char *)&i;
}


/*
 * 整数计数器转换成buffer计数器
 */
void counter2buffer(unsigned long int icounter, unsigned char szcounter[16]) {
    // unsigned char szcounter[16] = {0x00};
    memset(szcounter, 0, 16);
    unsigned int int_size = sizeof(unsigned long int);

    if (is_litttle_endian()) {
        for(int i=0; i<int_size; i++) {
            szcounter[15-i] = *((unsigned char *)&icounter + i); 
        }
    } else {
        memcpy(szcounter + 16- int_size, &icounter, int_size);
    }

}


// SM4 相关接口
SDK_API int SM4Ecb_Encrypt(char *in, int inlen, char *key, char *out) {
    printf("*************** Enter: %s\n", "SM4Ecb_Encrypt");
    return 1;
}


SDK_API int SM4Ecb_Decrypt(char *in, int inlen, char *key, char *out) {
    printf("*************** Enter: %s\n", "SM4Ecb_Decrypt");
    return 1;
}


SDK_API int SM4_Encrypt(char *in, int inlen, char key[16], char *out) {
    printf("*************** Enter: %s\n", "SM4_Encrypt");
    return 1;
}

SDK_API int SM4_Decrypt(char *in, int inlen, char key[16], char *out) {
    printf("*************** Enter: %s\n", "SM4_Decrypt");
    return 1;
}

/*
 * iv = counter  
 * 低位 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 高位
 * 低位 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 高位
 */
SDK_API int SM4CTR_Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, long unsigned int icounter, unsigned char *ciphertext) {
    printf("Enter: %s", __FUNCTION__);

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // long unsigned int counter, 
    unsigned char iv[16];
    counter2buffer(icounter, iv);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_sms4_ctr(), NULL, key, iv)) {
        return -1;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        return -1;
    }

    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        return -1;
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;

}

SDK_API int SM4CTR_Decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, long unsigned int icounter, unsigned char *plaintext) {
    printf("Enter: %s", __FUNCTION__);
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    // long unsigned int counter, 
    unsigned char iv[16];
    counter2buffer(icounter, iv);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_sms4_ctr(), NULL, key, iv)) {
        return -1;
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        return -1;
    }

    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        return -1;
    }

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
