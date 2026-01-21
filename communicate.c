#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "crypt.c"
#include "file.c"

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"

// client.c deki değişkenler
extern int chatReady;
extern int chatActive;
extern unsigned char currentAESKey[32];
extern EVP_PKEY *RSAKeyPair;
extern EVP_PKEY *otherClientPublicKey;

// SEND FUNCTIONS

void sendPacket(int socket, char *packet)
{
    long totalSize = strlen(packet) + 5; // 4(|END) + 1(\0) = 5 karakter
    char *finalPacket = (char *)malloc(totalSize);

    if (finalPacket)
    {
        sprintf(finalPacket, "%s|END", packet); // paketin sonuna göndermeden önce |END eklendi

        send(socket, finalPacket, strlen(finalPacket), 0);

        free(finalPacket);
    }
}

// TEXT

void sendText(int socket, char *message)
{
    unsigned char cipherText[2048];
    int cipherLength = encryptWithAES((unsigned char *)message, strlen(message), currentAESKey, cipherText);
    char *base64Text = encodeBase64(cipherText, cipherLength);
    long packetSize = strlen(base64Text) + 6; // TEXT| + \n = 6 karakter
    char *packet = (char *)malloc(packetSize);
    sprintf(packet, "TEXT|%s", base64Text);

    sendPacket(socket, packet);

    free(packet);
    free(base64Text);
}

// FILE

void sendFile(int socket, char *fileName)
{
    long fileSize;
    unsigned char *fileData = readFile(fileName, &fileSize);

    if (fileData != NULL)
    {
        printf(GREEN "[+] " RESET "File %s (%ld byte) found. Encrypting...\n", fileName, fileSize);

        unsigned char *fileCipherText = (unsigned char *)malloc(fileSize + 2048);
        if (fileCipherText == NULL)
        {
            printf(RED "[-] " RESET "Memory Error!\n");
            free(fileData);
        }

        int cipherLen = encryptWithAES(fileData, (int)fileSize, currentAESKey, fileCipherText);
        char *base64Data = encodeBase64(fileCipherText, cipherLen);
        long packetSize = strlen(fileName) + strlen(base64Data) + 50; // 20 yetmedi 50 yapıldı
        char *bigPacket = (char *)malloc(packetSize);                 // yer ayır
        sprintf(bigPacket, "FILE|%s|%s", fileName, base64Data);

        sendPacket(socket, bigPacket);
        printf(GREEN "[+] " RESET "File sent successfully.\n");

        free(fileData);
        free(fileCipherText);
        free(base64Data);
        free(bigPacket);
    }
    else
    {
        printf(RED "[-] " RESET "File not found!\n");
    }
}

// KEY

void sendKey(int socket, char *tag, char *keyData)
{
    char packet[4096];
    sprintf(packet, "%s|%s", tag, keyData);
    sendPacket(socket, packet);
}

// RECEIVE FUNCTIONS

int receivePacket(int socket, char *buffer)
{
    char *firstSeparator = strchr(buffer, '|');

    if (firstSeparator == NULL)
    {
        return 1;
    }

    *firstSeparator = '\0'; // Stringi ikiye böl
    char *tag = buffer;
    char *data = firstSeparator + 1;

    // TAG = TEXT ise

    if (strcmp(tag, "TEXT") == 0)
    {
        if (chatReady == 1)
        {
            int length;
            unsigned char *cipherRaw = decodeBase64(data, strlen(data), &length);

            if (cipherRaw)
            {
                unsigned char *decryptedText = (unsigned char *)malloc(length + 1024);
                memset(decryptedText, 0, length + 1024);
                int decryptLength = decryptWithAES(cipherRaw, length, currentAESKey, decryptedText);
                if (decryptLength > 0)
                {
                    if (strstr((char *)decryptedText, "/exit") != NULL)
                    {
                        printf("\r\033[K"); // boş you: sil
                        printf(RED "[-] " RESET "Other client left.\n");
                        free(cipherRaw);
                        return 0;
                    }

                    printf("\r\033[K");
                    printf(YELLOW "Other Client:" RESET " %s\n", decryptedText);
                    printf("You: ");
                    fflush(stdout);
                }
                free(cipherRaw);
            }
        }
    }

    // TAG = FILE ise

    else if (strcmp(tag, "FILE") == 0)
    {
        char *secondSeperator = strchr(data, '|');
        if (secondSeperator != NULL)
        {
            *secondSeperator = '\0';

            char *fileName = data;                  // |'dan öncesi - dosyanın adı
            char *fileBase64 = secondSeperator + 1; // |'dan sonrası - veri
            printf("\r\033[K");                     // You: silmek için
            printf(YELLOW "[*] " RESET "File downloading: %s\n", fileName);

            int length;
            unsigned char *encryptedData = decodeBase64(fileBase64, strlen(fileBase64), &length);
            unsigned char *decryptedFile = (unsigned char *)malloc(length + 2048); // buffer too small hatası için 2048 eklendi

            if (decryptedFile != NULL)
            {
                int fileLength = decryptWithAES(encryptedData, length, currentAESKey, decryptedFile);
                if (fileLength > 0)
                {
                    char saveFileName[256];
                    sprintf(saveFileName, "ChatApp_%s", fileName); // dosya karışıklılığını engellemek için belki tarih eklenebilir
                    writeFile(saveFileName, decryptedFile, fileLength);
                }
                else
                {
                    printf(RED "[-] " RESET "The file not decrypted.\n");
                }
            }

            if (decryptedFile)
                free(decryptedFile);

            if (encryptedData)
                free(encryptedData);

            printf("You: ");
            fflush(stdout);
        }
    }

    // TAG = PUBLIC KEY ise

    else if (strcmp(tag, "PUBLICKEY") == 0)
    {
        if (chatReady == 0)
        {
            printf(GREEN "[+] " RESET "The public key is taken from other client.\n"); // debug
            otherClientPublicKey = strToPEM(data);
            char *publicStr = getPublicKey(RSAKeyPair);

            if (strcmp(publicStr, data) > 0)
            {
                printf(YELLOW "[*] " RESET "You are HOST. AES key sending to other client..\n");

                RAND_bytes(currentAESKey, 32);
                unsigned char encKey[512];
                int len = encryptRSA(otherClientPublicKey, currentAESKey, 32, encKey);
                char *b64Key = encodeBase64(encKey, len);

                sendKey(socket, "AESKEY", b64Key); // key olarak gönder
                printf(GREEN "[+] " RESET "The connection is secured with end to end encryption now!\n");
                printf("You: ");
                fflush(stdout);
                chatReady = 1; // uçtan uca mesajlaşma hazır
            }
            else
            {
                printf(YELLOW "[*] " RESET "Other client is host, AES key waiting other client..\n");
                sendKey(socket, "PUBLICKEY", publicStr);
            }
        }
    }

    // TAG = AES KEY ise

    else if (strcmp(tag, "AESKEY") == 0)
    {
        if (chatReady == 0)
        {
            printf(YELLOW "[*] " RESET "The aes key taken from other client. Decrypting...\n");
            int length;
            unsigned char *encryptData = decodeBase64(data, strlen(data), &length);

            decryptRSA(RSAKeyPair, encryptData, length, currentAESKey);
            printf(GREEN "[+] " RESET "The public key decrypted.\n");
            printf(GREEN "[+] " RESET "The connection is secured with end to end encryption now!\n");
            printf("You: ");
            fflush(stdout);
            chatReady = 1;
        }
    }

    return 1;
}