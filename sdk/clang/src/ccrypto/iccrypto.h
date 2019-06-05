#ifndef _ICCRYPTO_H_
#define _ICCRYPTO_H_

#define SDK_API __declspec(dllexport)

// SM2 相关接口
SDK_API int SM2_Genkey(char *pubkey, char *prikey);

SDK_API int SM2_Encrypt(char *pubkey, char *in);

SDK_API int SM2_Decrypt(char *prikey, char *in);

// SM3 相关接口
SDK_API int SM3_Encrypt(char *pubkey, char *in);

// SM4 相关接口
SDK_API int SM4Ecb_Encrypt(char *in, int inlen, char *key, char *out);

SDK_API int SM4Ecb_Decrypt(char *in, int inlen, char *key, char *out);

SDK_API int SM4_Encrypt(char *in, int inlen, char key[16], char *out);

SDK_API int SM4_Decrypt(char *in, int inlen, char key[16], char *out);

// pkcs7 相关接口
SDK_API int Pkcs7_Encrypt(char *certs, char *in, int inlen, char key[16], char *out);

SDK_API int Pkcs7_Decrypt(char *in, int inlen, char key[16], char *out);

// 文件 相关接口
SDK_API int File_Encrypt(char *infile, char *outfile);

SDK_API int File_Decrypt(char *infile, char *outfile);


#ifdef __cplusplus
}
#endif

#endif

// // SM4相关函数
// SDK_API int SM4CTR_Encrypt(cuchar *in, uchar *out, size_t len, cuchar key[16],
//     uchar iv[16], uchar ecount_buf[16], unsigned int *num);

// SDK_API int SM4CTR_Decrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num);
