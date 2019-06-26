#include <stdio.h>
#include "iccrypto.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>

struct MY_CMS_EncryptedContentInfo_st {
    ASN1_OBJECT *contentType;
    X509_ALGOR *contentEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedContent;
};
typedef struct MY_CMS_EncryptedContentInfo_st MY_CMS_EncryptedContentInfo;
DECLARE_ASN1_FUNCTIONS(MY_CMS_EncryptedContentInfo);

ASN1_SEQUENCE(MY_CMS_EncryptedContentInfo) = {
        ASN1_SIMPLE(MY_CMS_EncryptedContentInfo, contentType, ASN1_OBJECT),
        ASN1_SIMPLE(MY_CMS_EncryptedContentInfo, contentEncryptionAlgorithm, X509_ALGOR),
        ASN1_IMP_OPT(MY_CMS_EncryptedContentInfo, encryptedContent, ASN1_OCTET_STRING_NDEF, 0)
} ASN1_SEQUENCE_END(MY_CMS_EncryptedContentInfo)
IMPLEMENT_ASN1_FUNCTIONS(MY_CMS_EncryptedContentInfo)



SDK_API int Pkcs7_Encrypt(char *certs, char *in, int inlen, char key[16], char *out) {
    printf("*************** Enter: %s", "Pkcs7_Encrypt");
    // CMS_EncryptedContentInfo
    
    MY_CMS_EncryptedContentInfo *cms_ec;
    cms_ec = MY_CMS_EncryptedContentInfo_new();
    
    cms_ec->contentType  = OBJ_txt2obj("1.2.156.10197.6.1.4.2.1", 0);

    if (!cms_ec->encryptedContent) {
        cms_ec->encryptedContent = ASN1_OCTET_STRING_new();
        ASN1_STRING_set(cms_ec->encryptedContent, "abc", 3);
    }

    int dlen = 0;
    unsigned char*tempData = NULL;
    dlen = i2d_MY_CMS_EncryptedContentInfo(cms_ec, &tempData);


    return 1;
}

SDK_API int Pkcs7_Decrypt(char *in, int inlen, char key[16], char *out) {
    printf("*************** Enter: %s", "Pkcs7_Decrypt");
    return 1;
}