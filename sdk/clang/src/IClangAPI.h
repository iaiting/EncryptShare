#ifndef _ICLANGAPI_H_
#define _ICLANGAPI_H_
#include <crtdefs.h>

#define SDK_API __declspec(dllexport)

typedef unsigned char           uchar;
typedef const unsigned char     cuchar;

typedef unsigned short  u2;
typedef unsigned long   u4;
typedef signed char     s1;
typedef signed char     s2;
typedef signed char     s4;


#ifdef __cplusplus
extern "C" {
#endif


// 采用非压缩的方式产生SM2的公钥和私钥对，即产生的公钥前补充0x04  04|x|y
SDK_API int SM2_Genkey2buf(char *pubkey, char *prikey);

// 采用非压缩的方式产生SM2的公钥和私钥的hex字符串，即产生的公钥前补充0x04  04|x|y
SDK_API int SM2_Genkey2hex(char *pubkeyhex, int i_pubkeyhex_len, char *privkeyhex, int i_privkeyhex_len);

SDK_API int SM2_EncryptBuf2Hex(cuchar *pubkeyHex, cuchar *in_pbuf, size_t in_pbuf_len, uchar *out_ebuf, size_t *out_ebuf_len);

SDK_API int SM2_DecryptHex2Buf(cuchar *privkeyHex, cuchar *in_ehex, size_t in_ehex_len, uchar *out_mbuf, size_t *out_mbuf_len);

// pubkey_hexflag = 1: 公钥为16进制字符串
SDK_API int SM4_Encrypt(cuchar *key, cuchar *psBytes, size_t psBytes_len, uchar *eoBytes);

SDK_API int SM4_Decrypt(cuchar *key, cuchar *eoBytes, size_t eoBytes_len, uchar *moBytes);

////////////////////////////////////////////////////////////////////////////////////
SDK_API int SM4_CTREncrypt();

// #define SMS4_BLOCK_SIZE		16
SDK_API int SM4CTR_Encrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num);

SDK_API int SM4CTR_Decrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num);

SDK_API int SM4CTR_FileEncrypt(cuchar *in_file, cuchar *out_file, cuchar key[16], uchar iv[16]);

SDK_API int SM4CTR_FileDecrypt(cuchar *in_file, cuchar *out_file, cuchar key[16], uchar iv[16]);


// MY TEST
SDK_API void LOG_TEST();

////////////////////////////////////////////////////////////////////////////////////
// usb key 相关接口

#ifdef __cplusplus
}
#endif

#endif
