#include <stdio.h>
#include "../IClangAPI.h"

/******************************************************************************/
static void SM2_Genkey2hex_TEST() {
	char pubkeyhex[1024] = {0};
	char privkeyhex[1024] = {0};

	SM2_Genkey2hex(pubkeyhex, sizeof(pubkeyhex), privkeyhex, sizeof(privkeyhex));
}


/******************************************************************************/
static void SM2_Encrypt_TEST() {
	const unsigned char *pubkeyHex = "040A564E9528DEE0EFC758788AF755DCFCB4D4CA13DBCE45E39F07DB35407D20B73F69A29E1BD0DA8EFDFFAA283EEF8DA5423A644064F340A2C09F5BCF2108A3A2";
	const unsigned char *psBytes = "112233";
	int psBytes_len = strlen(psBytes);
	char out_ebuf_2[256] = {0};
	long out_ebuf_len_2 = sizeof(out_ebuf_2);
	SM2_EncryptBuf2Hex(pubkeyHex, psBytes, psBytes_len, out_ebuf_2, &out_ebuf_len_2);

	const unsigned char *privkeyHex = "3D4E676010C5357A07E7ACFBE602EC21457CF485888449FE3241A2E65B8F87A4";
	//char *in_ehex = "306F02206CAB9BEA88ABA6C3F4E2EACF251DF8541CF1551F91B53FFFC517653B956C801B022100E6EE0AA39F3D0FCEF97E3CC0F2CF6628133DCB93A07504E3353023A9123100F40420A6E9CD64B69AEE892394517C3F4A184E7827E30FC4884E90B6718AE4CD6D7F78040698DC51017AC8";
	char *in_ehex = out_ebuf_2;
	int in_ehex_len = strlen(in_ehex);
	char out_mbuf_1[256] = { 0 };
	long out_mbuf_len_1 = sizeof(out_ebuf_2);

	SM2_DecryptHex2Buf(privkeyHex, in_ehex, in_ehex_len, out_mbuf_1, &out_mbuf_len_1);
}



static void SM4_CTREncrypt_TEST() {
	cuchar key_e1[16] = {
        0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
        0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0
	};
	cuchar *in_e1 = "0123456789abcdef10123456789abcdef1";
	size_t len_e1 = strlen(in_e1);
	uchar iv_e1[16] = {
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	};
	uchar ecount_buf_e1[16] = {0x00};
	int offset_e1 = 0;

	uchar out_e1[4096] = {0};
	SM4CTR_Encrypt(in_e1, out_e1, len_e1, key_e1, iv_e1, ecount_buf_e1, &offset_e1);


	uchar out_et1[4096] = { 0 };
	uchar iv_et1[16] = {
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	};
	uchar ecount_buf_et1[16] = { 0x00 };
	offset_e1 = 0;
	SM4CTR_Encrypt(in_e1, out_et1, 16, key_e1, iv_et1, ecount_buf_et1, &offset_e1);

	uchar out_et2[4096] = { 0 };
	uchar iv_et2[16] = {
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x02,
	};
	uchar ecount_buf_et2[16] = { 0x00 };
	offset_e1 = 0;
	SM4CTR_Encrypt(in_e1+16, out_et2, 16, key_e1, iv_et2, ecount_buf_et2, &offset_e1);


	cuchar in_d1[4096] = {0};
	memcpy(in_d1, out_e1, len_e1);
	size_t len_d1 = 7; //len_e1;

	cuchar key_d1[16] = {
		0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
		0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0
	};

	uchar iv_d1[16] = {0x00};
	uchar ecount_buf_d1[16] = {0x00};
	unsigned int offset_d1 = 0;

	uchar out_d1[4096] = {0};
	SM4CTR_Decrypt(in_d1, out_d1, len_d1, key_d1, iv_d1, ecount_buf_d1, &offset_d1);

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
void SM4CTR_FileEncrypt_TEST() {
	cuchar *in_file = "c:\\tmp\\test1.txt";
	cuchar *out_file = "c:\\tmp\\test1.txt.e";
	cuchar key[16] = {0x00};
	uchar iv[16] = {0x05};
	SM4CTR_FileEncrypt(in_file, out_file, key, iv);


	cuchar *out_mfile = "c:\\tmp\\test1.txt.m";
	cuchar *in_efile = "c:\\tmp\\test1.txt.e";
	SM4CTR_FileDecrypt(in_efile, out_mfile, key, iv);
}

void LOG_TEST_TEST() {
	LOG_TEST();
}


/******************************************************************************/
int main(int argc, char *argv[]) {
	printf("Enter main Function: \012");
	LOG_TEST_TEST();
	return;

	// SM4_CTREncrypt_TEST();
	return;

	time_t t;
	struct tm *timeinfo;
	time(&t);
	timeinfo = localtime(&t);
	printf("时间：%s\n", asctime(timeinfo));  //以字符串形式输出localtime本地时间

	SM4CTR_FileEncrypt_TEST();


	time(&t);
	timeinfo = localtime(&t);
	printf("时间：%s\n", asctime(timeinfo));  //以字符串形式输出localtime本地时间


	// SM2_Genkey2hex_TEST();
	SM2_Encrypt_TEST();
    return 0;
}