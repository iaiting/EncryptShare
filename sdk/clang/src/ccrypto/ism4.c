#include <stdio.h>
#include "iccrypto.h"

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

//SDK_API int SM4CTR_Encrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num) {
//        printf("Enter: %s", __FUNCTION__);
//        return 0;
//}
//
//SDK_API int SM4CTR_Decrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num) {
//    printf("Enter: %s", __FUNCTION__);
//    return 0;
//}
