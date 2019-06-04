#include <stdio.h>
#include "iccrypto.h"

SDK_API int SM4CTR_Encrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num) {
        printf("Enter: %s", __FUNCTION__);
        return 0;
}

SDK_API int SM4CTR_Decrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num) {
    printf("Enter: %s", __FUNCTION__);
    return 0;
}
