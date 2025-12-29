#include <openssl/evp.h> //encode/decode işlemleri için
#include <openssl/aes.h> //encryption aes
#include <openssl/bio.h> //basic i/o
// #include <openssl/pem.h> //şifreli verileri depolamak için
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/rand.h> //random num
#include <string.h>
#include <stdlib.h> //malloc için

static unsigned char *KEY = (unsigned char *)"32bytelikanahtar32bytelikanahtar"; // AES 256bit = 32byte
static unsigned char *InitialVector = (unsigned char *)"16bytelikanahtar";

void handleError(void)
{
    ERR_print_errors_fp(stderr);
    abort(); // hata alınca kapat
}

int encryptWithAES(unsigned char *plainText, int plainTextLength, unsigned char *key, unsigned char *cipherText)
{
    EVP_CIPHER_CTX *ctx;
    int length;
    int cipherTextLength;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleError();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, InitialVector) != 1) // AES 256 alg. seçildi. cbc zincirleme şifreler. ecb den daha güvenli.
    {
        handleError();
    }

    if (EVP_EncryptUpdate(ctx, cipherText, &length, plainText, plainTextLength) != 1) // metni parçalarıyla şifreleme
    {
        handleError();
    }

    cipherTextLength = length;

    if (EVP_EncryptFinal_ex(ctx, cipherText + length, &length) != 1) // şifrleme sonunda boşluklar kullanmak için
    {
        handleError();
    }

    cipherTextLength += length;

    EVP_CIPHER_CTX_free(ctx); // ctx'i bellekten siler
    return cipherTextLength;
}

int decryptWithAES(unsigned char *cipherText, int cipherTextLength, unsigned char *key, unsigned char *plainText)
{
    EVP_CIPHER_CTX *ctx;
    int length;
    int plainTextLength;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleError();
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, InitialVector) != 1)
    {
        handleError();
    }

    if (EVP_DecryptUpdate(ctx, plainText, &length, cipherText, cipherTextLength) != 1)
    {
        handleError();
    }

    plainTextLength = length;

    if (EVP_DecryptFinal_ex(ctx, plainText + length, &length) != 1)
    {
        handleError();
    }

    plainTextLength += length;

    EVP_CIPHER_CTX_free(ctx);
    plainText[plainTextLength] = '\0'; // NULL = \0 cümleyi bitirir
    return cipherTextLength;
}

char *encodeBase64(const unsigned char *input, int length)
{
    BIO *bmem, *base64;
    BUF_MEM *bptr;

    base64 = BIO_new(BIO_f_base64()); // metni base64 formatında yaz
    bmem = BIO_new(BIO_s_mem());      // hafızada yer aç
    base64 = BIO_push(base64, bmem);
    BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(base64, input, length);
    BIO_flush(base64);
    BIO_get_mem_ptr(base64, &bptr);

    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(base64);
    return (buff);
}

unsigned char *decodeBase64(const char *input, int length, int *outLength)
{
    BIO *base64, *bmem;
    unsigned char *buffer = (unsigned char *)malloc(length);
    memset(buffer, 0, length);

    base64 = BIO_new(BIO_f_base64());
    BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)input, length);
    bmem = BIO_push(base64, bmem);

    *outLength = BIO_read(base64, buffer, length);
    BIO_free_all(base64);

    return (buffer);
}
