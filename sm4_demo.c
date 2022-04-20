#include "sm4_demo.h"
#include "print.h"
#include <openssl/evp.h>

enum {
    FAIL = -1,
};
static const uint8_t key[16] = {
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
};
static const uint8_t iv[16] = {
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
};
static const uint8_t plain[239] = {
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
};
static int plainLen = sizeof(plain);
static uint8_t encryptedCipher[256] = { 0 };
static int encryptedCipherLen = 0;
static uint8_t decryptedPlain[256] = { 0 };
static int decryptedPlainLen = 0;

int sm4_encrypt_demo(){
    encryptedCipherLen = 0;

	EVP_CIPHER_CTX *ctx;
    int res;
	ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOGE("");
        return FAIL;
    }
    const EVP_CIPHER *mode = EVP_sm4_cbc();
    if (mode == NULL) {
        LOGE("");
        return FAIL;
    }
	res = EVP_EncryptInit(ctx, mode, key, iv);
    if (res != 1) {
        LOGE("res = %d, 0x%x", res, res);
        return FAIL;
    }
    int paddingSize = EVP_CIPHER_CTX_block_size(ctx);
    LOGI("paddingSize is %d", paddingSize);
	res = EVP_CIPHER_CTX_set_padding(ctx, plainLen % paddingSize);
    if (res != 1) {
        LOGE("res = %d, 0x%x", res, res);
        return FAIL;
    }

    const int updateSize = paddingSize * 3; // updateSize must be an integer multiple of paddingSize
    int offset = 0;
    for(; offset + updateSize < plainLen; offset += updateSize) {
        int updateOutLen = 0;
        res = EVP_EncryptUpdate(ctx, encryptedCipher + offset, &updateOutLen, plain + offset, updateSize);
        if (res != 1) {
            LOGE("offset = %d, res = %d, 0x%x", offset, res, res);
            return FAIL;
        }
        encryptedCipherLen += updateOutLen;
    }
    if (offset < plainLen) {
        int updateOutLen = 0;
        res = EVP_EncryptUpdate(ctx, encryptedCipher + offset, &updateOutLen, plain + offset, plainLen - offset);
        if (res != 1) {
            LOGE("offset = %d, res = %d, 0x%x", offset, res, res);
            return FAIL;
        }
        encryptedCipherLen += updateOutLen;
        offset += updateOutLen;
    }

    int finalOutLen = 0;
    res = EVP_EncryptFinal(ctx, encryptedCipher + offset, &finalOutLen);
    if (res != 1) {
        LOGE("res = %d, 0x%x", res, res);
        return FAIL;
    }
    encryptedCipherLen += finalOutLen;
    PrintBuffer("cipher", encryptedCipher, encryptedCipherLen);
    return 0;
}

int sm4_decrypt_demo(){
    decryptedPlainLen = 0;

	EVP_CIPHER_CTX *ctx;
    int res;
	ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOGE("");
        return FAIL;
    }
    const EVP_CIPHER *mode = EVP_sm4_cbc();
    if (mode == NULL) {
        LOGE("");
        return FAIL;
    }
	res = EVP_DecryptInit(ctx, mode, key, iv);
    if (res != 1) {
        LOGE("res = %d, 0x%x", res, res);
        return FAIL;
    }
    int paddingSize = EVP_CIPHER_CTX_block_size(ctx);
    LOGI("paddingSize is %d", paddingSize);
	res = EVP_CIPHER_CTX_set_padding(ctx, encryptedCipherLen % paddingSize);
    if (res != 1) {
        LOGE("res = %d, 0x%x", res, res);
        return FAIL;
    }
    const int updateSize = paddingSize * 5; // updateSize must be an integer multiple of paddingSize
    int offset = 0;
    for (; offset + updateSize < encryptedCipherLen; offset += updateSize) {
        int updateOutLen = 0;
        res = EVP_DecryptUpdate(ctx, decryptedPlain + offset, &updateOutLen, encryptedCipher + offset, updateSize);
        if (res != 1) {
            LOGE("offset = %d, res = %d, 0x%x", offset, res, res);
            return FAIL;
        }
        decryptedPlainLen += updateOutLen;
    }
    if (offset < plainLen) {
        int updateOutLen = 0;
        res = EVP_DecryptUpdate(ctx, decryptedPlain + offset, &updateOutLen, encryptedCipher + offset, encryptedCipherLen - offset);
        if (res != 1) {
            LOGE("offset = %d, res = %d, 0x%x", offset, res, res);
            return FAIL;
        }
        decryptedPlainLen += updateOutLen;
        offset += updateOutLen;
    }
    int finalOutLen = 0;
    res = EVP_DecryptFinal(ctx, decryptedPlain + offset, &finalOutLen);
    if (res != 1) {
        LOGE("res = %d, 0x%x", res, res);
        return FAIL;
    }
    decryptedPlainLen += finalOutLen;
    PrintBuffer("decryptedPlain", decryptedPlain, decryptedPlainLen);
    return 0;
}
