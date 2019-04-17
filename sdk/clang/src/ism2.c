#include "IClangAPI.h"
#include "openssl/sm2.h"
//#include "openssl/ec_lcl.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

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

