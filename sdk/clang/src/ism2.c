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
SDK_API int SM2_Genkey2hex(char *pubkeyhex, char *privkeyhex) {
	EC_KEY *ec_key = NULL;
	const EC_POINT *ec_point = NULL;
	char *pubkeyhex_tmp = NULL;
	const BIGNUM *priv_key = NULL;
	char *privkeyhex_tmp = NULL;

	if (!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		goto end;
	}

	if (!EC_KEY_generate_key(ec_key)) {
		goto end;
	}

	if (!(ec_point = EC_KEY_get0_public_key(ec_key))) {
		goto end;
	}

	// POINT_CONVERSION_COMPRESSED
	// POINT_CONVERSION_UNCOMPRESSED
	// POINT_CONVERSION_HYBRID
	pubkeyhex_tmp = EC_POINT_point2hex(EC_KEY_get0_group(ec_key), ec_point, POINT_CONVERSION_UNCOMPRESSED, BN_CTX_new());
	priv_key = EC_KEY_get0_private_key(ec_key);
	privkeyhex_tmp = BN_bn2hex(priv_key);

	memcpy(pubkeyhex, pubkeyhex_tmp, strlen(pubkeyhex_tmp));
	memcpy(privkeyhex, privkeyhex_tmp, strlen(privkeyhex_tmp));

end:
	EC_KEY_free(ec_key);
	OPENSSL_free(pubkeyhex_tmp);
	OPENSSL_free(privkeyhex_tmp);

	return 0;
}


SDK_API int SM2_Encrypt(cuchar *pubkey, int pubkey_hexflag, cuchar *psBytes, size_t psBytes_len, uchar **eoBytes, size_t *eo_len) {

	//EC_GROUP *sm2p256v1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	EC_KEY *sm2key = NULL;
	int type = NID_sm3;
	uint8_t inBuf[200] = { "123456789aaaaaaaaabbbbbbbbbbbbbbbbbbcccccccccccccccccccddddddddddddddddddddeeeeeeeeeeeeeeeeeeefffffffffffffffffffff123456789" };
	uint8_t outBuf[200] = { 0 };
	uint8_t tmpBuf[200] = { 0 };
	size_t inLen = 50;
	size_t outLen = sizeof(outBuf);
	size_t tmpLen = sizeof(tmpBuf);
	int ret = 0;


	puts("PlainText:"); PrintData(inBuf, inLen); puts("");

	// Get sm2 key
	sm2key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	ret = EC_KEY_generate_key(sm2key);
	if (ret != 1)
	{
		puts("EC_KEY_generate_key failed!");
		return;
	}

	// Encrypt
	ret = SM2_encrypt(type, inBuf, inLen, outBuf, &outLen, sm2key);
	if (ret != 1)
	{
		printf("SM2_encrypt failed! [0x%08X]\n", ERR_get_error());
		ERR_print_errors_fp(stderr);
		return;
	}
	else
	{
		puts("Encrypt success!");
		puts("CipherText:"); PrintData(outBuf, outLen); puts("");
	}



	SM2CiphertextValue *cv = NULL;
	char *tp = outBuf;
	long inlen = outLen;
	cv = d2i_SM2CiphertextValue(NULL, &tp, (long)inlen);

	// Get output length
	tmpLen = 0;
	ret = SM2_decrypt(type, outBuf, outLen, NULL, &tmpLen, sm2key);
	if (ret != 1)
	{
		puts("SM2_decrypt failed on get output-length!");
		return;
	}

	// Decrypt
	ret = SM2_decrypt(type, outBuf, outLen, tmpBuf, &tmpLen, sm2key);
	if (ret != 1 && inLen != tmpLen && 0 != CRYPTO_memcmp(tmpBuf, inBuf, tmpLen))
	{
		puts("SM2_decrypt failed!");
		return;
	}
	else
	{
		puts("Decrypt success!");
		puts("DecryptedText:"); PrintData(tmpBuf, tmpLen); puts((char*)tmpBuf); puts("");
	}

}


SDK_API int SM2_Decrypt(const unsigned char *es, unsigned char *mo) {
	return 10;
}

