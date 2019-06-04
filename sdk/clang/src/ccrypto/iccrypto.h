#ifndef _ICCRYPTO_H_
#define _ICCRYPTO_H_

// #include <crtdefs.h>
typedef unsigned char           uchar;
typedef const unsigned char     cuchar;

#define SDK_API __declspec(dllexport)

// 采用非压缩的方式产生SM2的公钥和私钥对，即产生的公钥前补充0x04  04|x|y
SDK_API int SM2_Genkey(char *pubkey, char *prikey);

// SM4相关函数
SDK_API int SM4CTR_Encrypt(cuchar *in, uchar *out, size_t len, cuchar key[16],
    uchar iv[16], uchar ecount_buf[16], unsigned int *num);

SDK_API int SM4CTR_Decrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num);

#ifdef __cplusplus
}
#endif

#endif