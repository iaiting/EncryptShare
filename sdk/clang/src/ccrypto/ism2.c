#include <stdio.h>
#include "iccrypto.h"

SDK_API int SM2_Genkey(char *pubkey, char *prikey) {
    printf("*************** Enter: %s", "SM2_Genkey");
    return 1;
}

SDK_API int SM2_Encrypt(char *pubkey, char *in) {
    printf("*************** Enter: %s", "SM2_Encrypt");
    return 1;
}

SDK_API int SM2_Decrypt(char *prikey, char *in) {
    printf("*************** Enter: %s", "SM2_Decrypt");
    return 1;
}