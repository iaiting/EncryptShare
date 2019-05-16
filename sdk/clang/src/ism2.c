#include "IClangAPI.h"
#include "openssl/sm2.h"
#include "openssl/ec_lcl.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/sm2_lcl.h>


void PrintData(uint8_t* data, uint32_t len)
{
	for (uint32_t i = 0; i < len; i++)
	{
		printf("%02X ", data[i]);
		if ((i % 16) == 15 && (i != (len - 1)))
		{
			puts("");
		}
	}
	puts("");
}


/******************************************************************************/
static void safe_copy_buf(unsigned char* dst, int i_len_dst, unsigned char* src, int i_len_src) {
    int i_len_to_copy = 0;

    do {
        if ((NULL == dst) || (NULL == src)) {
            break;
        }

        i_len_to_copy = (i_len_src < i_len_dst) ? i_len_src : i_len_dst;
        memset(dst, 0, i_len_dst);

        if (i_len_to_copy <= 0) {
            break;
        }

        memcpy(dst, src, i_len_to_copy);
    } while (0);
}

/******************************************************************************/
char *MY_OPENSSL_buf2hexstr(const unsigned char *buffer, long len)
{
    const static char hexdig[] = "0123456789ABCDEF";
    char *tmp, *q;
    const unsigned char *p;
    int i;

    if (len == 0)
    {
        return OPENSSL_zalloc(1);
    }

    if ((tmp = OPENSSL_malloc(len * 3)) == NULL) {
        CRYPTOerr(CRYPTO_F_OPENSSL_BUF2HEXSTR, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    q = tmp;
    for (i = 0, p = buffer; i < len; i++, p++) {
        *q++ = hexdig[(*p >> 4) & 0xf];
        *q++ = hexdig[*p & 0xf];
        // *q++ = ':';
    }
    // q[-1] = 0;
	*q = 0;
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(tmp, tmp, q - tmp - 1);
#endif

    return tmp;
}



/******************************************************************************/
unsigned char *MY_OPENSSL_hexstr2buf(const char *str, long *len)
{
    unsigned char *hexbuf, *q;
    unsigned char ch, cl;
    int chi, cli;
    const unsigned char *p;
    size_t s;

    s = strlen(str);
    if ((hexbuf = OPENSSL_malloc(s >> 1)) == NULL) {
        CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (p = (const unsigned char *)str, q = hexbuf; *p; ) {
        ch = *p++;
        if (ch == ':')
            continue;
        cl = *p++;
        if (!cl) {
            CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF,
                      CRYPTO_R_ODD_NUMBER_OF_DIGITS);
            OPENSSL_free(hexbuf);
            return NULL;
        }
        cli = OPENSSL_hexchar2int(cl);
        chi = OPENSSL_hexchar2int(ch);
        if (cli < 0 || chi < 0) {
            OPENSSL_free(hexbuf);
            CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, CRYPTO_R_ILLEGAL_HEX_DIGIT);
            return NULL;
        }
        *q++ = (unsigned char)((chi << 4) | cli);
    }

    if (len)
        *len = q - hexbuf;
    return hexbuf;
}

/******************************************************************************/
static char* MY_OPENSSL_EC_KEY_privatekey2hex(EC_KEY *ec_key) {
	const BIGNUM *private_key;
	private_key = EC_KEY_get0_private_key(ec_key);
	if (!private_key) {
		return NULL;
	}
	return BN_bn2hex(private_key);
}



/******************************************************************************/
static char* MY_OPENSSL_EC_KEY_pubkey2hex(EC_KEY *ec_key) {
	const EC_POINT *ec_point = NULL;
	const EC_GROUP *ec_group = NULL;

	if (!(ec_point = EC_KEY_get0_public_key(ec_key))) {
		return NULL;
	}

	if (!(ec_group = EC_KEY_get0_group(ec_key))) {
		return NULL;
	}

	// 三种模式
	// POINT_CONVERSION_COMPRESSED
	// POINT_CONVERSION_UNCOMPRESSED
	// POINT_CONVERSION_HYBRID
	return EC_POINT_point2hex(ec_group, ec_point, POINT_CONVERSION_UNCOMPRESSED, BN_CTX_new());
}


/******************************************************************************/
SDK_API int SM2_Genkey2buf(char *pubkey, char *prikey) {
	EC_KEY *ec_key = NULL;

	if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		goto end;
	}

	if (!EC_KEY_generate_key(ec_key)) {
		goto end;
	}

	end:
	return 0;
}

/******************************************************************************/
SDK_API int SM2_Genkey2hex(char *pubkeyhex, int i_pubkeyhex_len, char *privkeyhex, int i_privkeyhex_len) {
	int ret = 0;
	EC_KEY *ec_key = NULL;
	char *pubkeyhex_tmp = NULL;
	char *privkeyhex_tmp = NULL;

	if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		goto end;
	}

	if (!EC_KEY_generate_key(ec_key)) {
		goto end;
	}

	if (!(pubkeyhex_tmp = MY_OPENSSL_EC_KEY_pubkey2hex(ec_key))) {
		goto end;
	}

	if (!(privkeyhex_tmp = MY_OPENSSL_EC_KEY_privatekey2hex(ec_key))) {
		goto end;
	}


	safe_copy_buf(pubkeyhex, i_pubkeyhex_len, pubkeyhex_tmp, strlen(pubkeyhex_tmp));

	safe_copy_buf(privkeyhex, i_privkeyhex_len, privkeyhex_tmp, strlen(privkeyhex_tmp));

	ret = 1;

end:
	EC_KEY_free(ec_key);
	OPENSSL_free(pubkeyhex_tmp);
	OPENSSL_free(privkeyhex_tmp);

	return ret;
}


////////////////////////////////////////////////////////////////////////////////
static int _sm2_encrypt(cuchar *pubkeyHex, cuchar *in, size_t in_len, uchar *out, size_t *out_len) {
	int ret = 0;

	EC_KEY *ec_key = NULL;
	EC_POINT *ec_point = NULL;

	if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		goto end;
	}

	if (!(ec_point = EC_POINT_hex2point(EC_KEY_get0_group(ec_key), pubkeyHex, NULL, BN_CTX_new()))) {
		goto end;
	}

	if (!EC_KEY_set_public_key(ec_key, ec_point)) {
		goto end;
	}

	if (!SM2_encrypt(NID_sm3, in, in_len, out, out_len, ec_key)) {
		goto end;
	 }

	ret = 1;

end:
	EC_KEY_free(ec_key);
	EC_POINT_free(ec_point);

	return ret;
}

// 040A564E9528DEE0EFC758788AF755DCFCB4D4CA13DBCE45E39F07DB35407D20B73F69A29E1BD0DA8EFDFFAA283EEF8DA5423A644064F340A2C09F5BCF2108A3A2
// 3D4E676010C5357A07E7ACFBE602EC21457CF485888449FE3241A2E65B8F87A4
/******************************************************************************/
SDK_API int SM2_EncryptBuf2Hex(cuchar *pubkeyHex, cuchar *in_pbuf, size_t in_pbuf_len, uchar *out_ebuf, size_t *out_ebuf_len) {
	int ret = 0;

	size_t out_len_tmp = 0;
	uchar *out_tmp = NULL;
	uchar *out_ebuf_hex = NULL;

	// asn1编码后的总长度为 inlen + 96 + (10到12), 最大为 inlen + 108
	out_len_tmp = in_pbuf_len + 109;
	out_tmp = OPENSSL_malloc(out_len_tmp);
    if (!out_tmp) {
		goto end;
	}

	if (!_sm2_encrypt(pubkeyHex, in_pbuf, in_pbuf_len, out_tmp, &out_len_tmp)) {
		goto end;
	}

	if (!(out_ebuf_hex = MY_OPENSSL_buf2hexstr(out_tmp, out_len_tmp))) {
		goto end;
	}

	if(*out_ebuf_len < out_len_tmp*2) {
		goto end;
	}

	memcpy(out_ebuf, out_ebuf_hex, out_len_tmp * 2);
	*out_ebuf_len = out_len_tmp * 2;

	ret = 1;

end:
	OPENSSL_free(out_tmp);
	OPENSSL_free(out_ebuf_hex);
	return ret;
}


// 040A564E9528DEE0EFC758788AF755DCFCB4D4CA13DBCE45E39F07DB35407D20B73F69A29E1BD0DA8EFDFFAA283EEF8DA5423A644064F340A2C09F5BCF2108A3A2
// 3D4E676010C5357A07E7ACFBE602EC21457CF485888449FE3241A2E65B8F87A4
////////////////////////////////////////////////////////////////////////////////
static int _sm2_decrypt(cuchar *privkeyHex, cuchar *in, size_t in_len, uchar *out, size_t *out_len) {
	int ret = 0;

	EC_KEY *ec_key = NULL;
	BIGNUM *privkey = NULL;
	int out_len_tmp = 0;

	if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		goto end;
	}

	if(!BN_hex2bn(&privkey, privkeyHex)) {
		goto end;
	}

	if (!EC_KEY_set_private_key(ec_key, privkey)) {
		goto end;
	}

	// 首先获取密文的长度 out_len_tmp，申请空间
	// if (!SM2_decrypt(NID_sm3, in, in_len, NULL, &out_len_tmp, ec_key)) {
	// 	goto end;
	// }

	// 解密
	if (!SM2_decrypt(NID_sm3, in, in_len, out, out_len, ec_key)) {
		goto end;
	}

	ret = 1;

end:
	EC_KEY_free(ec_key);
	BN_clear_free(privkey);

	return ret;
}

////////////////////////////////////////////////////////////////////////////////
SDK_API int SM2_DecryptHex2Buf(cuchar *privkeyHex, cuchar *in_ehex, size_t in_ehex_len, uchar *out_mbuf, size_t *out_mbuf_len) {
	int ret = 0;
	char *in_ebuf = NULL;

	if (!(in_ebuf = MY_OPENSSL_hexstr2buf(in_ehex, NULL))) {
		goto end;
	}

	if (!_sm2_decrypt(privkeyHex, in_ebuf, in_ehex_len/2, out_mbuf, out_mbuf_len)) {
		goto end;
	}
	ret = 1;

end:
	OPENSSL_free(in_ebuf);
	return ret;
}

