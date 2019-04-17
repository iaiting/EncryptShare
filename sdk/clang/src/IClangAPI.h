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
/*******************************************************************************
    pubkey  : 返回的公钥字节序
    prikey  : 返回的私钥字节序
*******************************************************************************/
SDK_API int SM2_Genkey2buf(char *pubkey, char *prikey);

// 采用非压缩的方式产生SM2的公钥和私钥的hex字符串，即产生的公钥前补充0x04  04|x|y
/*******************************************************************************
    pubkeyhex  : 返回的公钥hex字符串
    privkeyhex : 返回的私钥hex字符串
*******************************************************************************/
SDK_API int SM2_Genkey2hex(char *pubkeyhex, char *privkeyhex);

// pubkey_hexflag = 0: 公钥为bytes
// pubkey_hexflag = 1: 公钥为16进制字符串
SDK_API int SM2_Encrypt(cuchar *pubkey, int pubkey_hexflag, cuchar *psBytes, size_t psBytes_len, uchar **eoBytes, size_t *eo_len);

SDK_API int SM2_Decrypt(cuchar *prikey, int prikey_hexflag, cuchar *eoBytes, size_t eoBytes_len, uchar **moBytes, size_t *mo_len);

SDK_API int SM2_EncryptBytes2Hex(cuchar *pubkey, int pubkey_hexflag, cuchar *psBytes, size_t psBytes_len, uchar **eoHex);

SDK_API int SM2_DecryptHex2Bytes(cuchar *pubkey, int pubkey_hexflag, cuchar *psBytes, size_t psBytes_len, uchar **eoHex);


// pubkey_hexflag = 1: 公钥为16进制字符串
SDK_API int SM4_Encrypt(cuchar *key, cuchar *psBytes, size_t psBytes_len, uchar *eoBytes);

SDK_API int SM4_Decrypt(cuchar *key, cuchar *eoBytes, size_t eoBytes_len, uchar *moBytes);

#ifdef __cplusplus
}
#endif

#endif
