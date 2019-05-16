#include "IClangAPI.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

# include <openssl/sms4.h>
#define DATA_LEN 32

#define EVP_MAX_KEY_LENGHT 64
#define BUFFERSIZE 4096

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



SDK_API int SM4_CTREncrypt() {
    int ret = 0;
    ret = 1;

// void sms4_ctr128_encrypt(const unsigned char *in, unsigned char *out,
// 	size_t len, const sms4_key_t *key, unsigned char *iv,
// 	unsigned char ecount_buf[SMS4_BLOCK_SIZE], unsigned int *num)

	sms4_key_t key;
    const unsigned char user_key[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        };

    const unsigned char iv1[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        };


	const unsigned char iv2[16] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	};
	sms4_set_encrypt_key(&key, user_key);


    char *in = "abc";
    size_t len = strlen(in);
    char out[256] = {0};
	char out_tmp[256] = { 0 };
    int num = 0;
    char ecount_buf[SMS4_BLOCK_SIZE] = {
            0x00
    };
	for (int i = 0; i < 2; i++) {
		sms4_ctr128_encrypt(in, out_tmp, len, &key, iv1, ecount_buf, &num);
		memcpy(out+len*i, out_tmp, len);
	}




	char out2[256] = { 0 };
	char ecount_buf_d[SMS4_BLOCK_SIZE] = {
			0x00
	};
	int num_d = 0;
	sms4_ctr128_encrypt(out, out2, 6, &key, iv2, ecount_buf_d, &num_d);

    return ret;
}


////////////////////////////////////////////////////////////////////////////////

static void _sm4ctr_encrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *offset) {
    sms4_key_t sms4_key;
    // sms4_set_decrypt_key(&sms4_key, key);
    // crt 模式解密也是用sms4_set_encrypt_key 而非用 sms4_set_decrypt_key
    sms4_set_encrypt_key(&sms4_key, key);

    sms4_ctr128_encrypt(in, out, len, &sms4_key, iv, ecount_buf, offset);
}

SDK_API int SM4CTR_Encrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num) {
    int ret = 0;
    _sm4ctr_encrypt(in, out, len, key, iv, ecount_buf, num);
    ret = 1;

    return ret;
}


SDK_API int SM4CTR_Decrypt(cuchar *in, uchar *out, size_t len, cuchar key[16], uchar iv[16], uchar ecount_buf[16], unsigned int *num) {
    int ret = 0;
    _sm4ctr_encrypt(in, out, len, key, iv, ecount_buf, num);

    ret = 1;
    return ret;
}



SDK_API int SM4CTR_FileEncrypt(cuchar *in_file, cuchar *out_file, cuchar key[16], uchar iv[16]) {
    int ret = 0;
    BIO *in_bio = BIO_new(BIO_s_file());
    if ((in_bio == NULL) || (BIO_read_filename(in_bio, in_file) <= 0)) {
        goto end;
    }

    BIO *out_bio = BIO_new(BIO_s_file());
    if ((out_bio == NULL) || (BIO_write_filename(out_bio, out_file) <= 0)) {
        goto end;
    }



    char ibuf[BUFFERSIZE] = {0};
    char obuf[BUFFERSIZE] = {0};
    int num = 0;
    uchar ecount_buf[16] = {0x00};

    int rlen;
    for (;;) {
        rlen = BIO_read(in_bio, ibuf, BUFFERSIZE);
        if (rlen <= 0) {
            break;
        }
        _sm4ctr_encrypt(ibuf, obuf, rlen, key, iv, ecount_buf, &num);
        if (BIO_write(out_bio, obuf, rlen) != rlen) {
            break;
        }
    }
    ret = 1;

end:
    BIO_free(in_bio);
    BIO_free(out_bio);
    return ret;
}

SDK_API int SM4CTR_FileDecrypt(cuchar *in_file, cuchar *out_file, cuchar key[16], uchar iv[16]) {
    int ret = 0;

    SM4CTR_FileEncrypt(in_file, out_file,  key, iv);

    ret = 1;

    return ret;


}