#include <openssl/evp.h> //encode/decode işlemleri için
#include <openssl/aes.h> //encryption aes
#include <openssl/rsa.h> //rsa keygen komutları için
#include <openssl/bio.h> //basic i/o
#include <openssl/pem.h> //rsa işlemleri
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/rand.h> //random num
#include <string.h>
#include <stdlib.h> //malloc için

static unsigned char *KEY = (unsigned char *)"32bytelikanahtar32bytelikanahtar"; // AES 256bit = 32byte

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
    unsigned char initialVector[16]; // her mesaj için rastgele

    if (!RAND_bytes(initialVector, 16))
        handleError(); // 16 byte'lık bir metin oluşturur.

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleError();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, initialVector) != 1)
        handleError(); // AES 256 alg. cbc zincirleme şifreler. ecb den daha güvenli.

    if (EVP_EncryptUpdate(ctx, cipherText + 16, &length, plainText, plainTextLength) != 1)
        handleError(); // metni parçalarıyla şifreleme

    cipherTextLength = length;

    if (EVP_EncryptFinal_ex(ctx, cipherText + 16 + length, &length) != 1)
        handleError(); // şifrleme sonunda boşluklar kullanmak için

    cipherTextLength += length;

    EVP_CIPHER_CTX_free(ctx); // ctx'i bellekten siler
    memcpy(cipherText, initialVector, 16);
    return cipherTextLength + 16;
}

int decryptWithAES(unsigned char *cipherText, int cipherTextLength, unsigned char *key, unsigned char *plainText)
{
    EVP_CIPHER_CTX *ctx;
    int length;
    int plainTextLength;
    unsigned char initialVector[16];

    memcpy(initialVector, cipherText, 16);

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleError();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, initialVector) != 1)
        handleError();

    if (EVP_DecryptUpdate(ctx, plainText, &length, cipherText + 16, cipherTextLength - 16) != 1)
        handleError();

    plainTextLength = length;

    if (EVP_DecryptFinal_ex(ctx, plainText + length, &length) != 1)
        handleError();

    plainTextLength += length;

    EVP_CIPHER_CTX_free(ctx);
    plainText[plainTextLength] = '\0'; // NULL = \0 cümleyi bitirir
    return plainTextLength;
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

EVP_PKEY *createRSAKey()
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx)
        handleError();

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        handleError();

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) <= 0)
        handleError(); // 1024 bitlik rsa key(artırılabilir)

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        handleError();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

char *getPublicKey(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);

    char *pemStr = NULL;
    long length = BIO_get_mem_data(bio, &pemStr);

    char *result = (char *)malloc(length + 1);
    memcpy(result, pemStr, length);
    result[length] = '\0';

    BIO_free(bio);
    return result;
}

EVP_PKEY *strToPEM(char *pemStr)
{
    BIO *bio = BIO_new_mem_buf(pemStr, -1);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    BIO_free(bio);
    return pkey;
}
int encryptRSA(EVP_PKEY *publicKey, unsigned char *plainData, int length, unsigned char *encryptedData)
{
    EVP_PKEY_CTX *ctx;
    size_t outLength;

    ctx = EVP_PKEY_CTX_new(publicKey, NULL);

    if (!ctx)
        handleError();

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        handleError();

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handleError(); // OAEP = güvenlik

    if (EVP_PKEY_encrypt(ctx, NULL, &outLength, plainData, length) <= 0)
        handleError(); // şifreli metnin tuttuğu alan

    if (EVP_PKEY_encrypt(ctx, encryptedData, &outLength, plainData, length) <= 0)
        handleError(); // şifreleme

    EVP_PKEY_CTX_free(ctx);
    return (int)outLength;
}

int decryptRSA(EVP_PKEY *privateKey, unsigned char *encryptedData, int length, unsigned char *decryptedData)
{
    EVP_PKEY_CTX *ctx;
    size_t outLength;

    ctx = EVP_PKEY_CTX_new(privateKey, NULL);

    if (!ctx)
        handleError();

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        handleError();

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handleError(); // OAEP = güvenlik

    if (EVP_PKEY_decrypt(ctx, NULL, &outLength, encryptedData, length) <= 0)
        handleError(); // şifreli metnin tuttuğu alan

    if (EVP_PKEY_decrypt(ctx, decryptedData, &outLength, encryptedData, length) <= 0)
        handleError(); // şifreleme

    EVP_PKEY_CTX_free(ctx);
    return (int)outLength;
}