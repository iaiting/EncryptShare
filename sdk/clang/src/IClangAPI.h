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
