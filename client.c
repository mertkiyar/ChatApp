#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "crypt.c"
#include "file.c"

#define PORT 6378

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"

int chatActive = 1; // exit için
int chatReady = 0;  // eşleşme için

EVP_PKEY *RSAKeyPair = NULL;
EVP_PKEY *otherClientPublicKey = NULL;
unsigned char currentAESKey[32];

void sendData(int socket, char *tag, char *data)
{
    char packet[2048];                   // 1024 yetmemiş olabilir diye 2048 oldu
    sprintf(packet, "%s|%s", tag, data); // TAG|DATA şeklinde gönderilir
    send(socket, packet, strlen(packet), 0);
}

void *receiveMessage(void *socket_desc)
{
    int socket = *(int *)socket_desc;
    // char buffer[4096]; resim ve ses dosyaları için çok küçük. 4kb mesajlara anca yetiyor
    char *buffer = (char *)malloc(15 * 1024 * 1024); // şu anlık 15mb olarak yeterli gibi artırılabilir.

    if (buffer == NULL)
    {
        printf(RED "[-] " RESET "Memory allocation failed\n");
        return NULL;
    }

    int readSize; // mesajdaki harf sayısı
    unsigned char *decrypedText = (unsigned char *)malloc(15 * 1024 * 1024);

    while ((readSize = recv(socket, buffer, 15 * 1024 * 1024, 0)) > 0) // 0'dan fazla harf varken
    {
        buffer[readSize] = '\0';
        memset(decrypedText, 0, 15 * 1024 * 1024);

        // TAG = FILE ise

        if (strncmp(buffer, "FILE", 4) == 0)
        {
            char *firstSeperator = strchr(buffer, '|');
            if (firstSeperator != NULL)
            {
                char *secondSeperator = strchr(firstSeperator + 1, '|');
                if (secondSeperator != NULL)
                {
                    *secondSeperator = '\0';

                    char *fileName = firstSeperator + 1;        // |'dan öncesi - dosyanın adı
                    char *fileDataBase64 = secondSeperator + 1; // |'dan sonrası - veri
                    printf("\r\033[K");                         // You: silmek için
                    printf(YELLOW "[*] " RESET "File downloading...\n");

                    int length;
                    unsigned char *encryptedData = decodeBase64(fileDataBase64, strlen(fileDataBase64), &length);

                    unsigned char *decryptedFile = (unsigned char *)malloc(length + 256); // buffer too small hatası içi 256 eklendi

                    if (decryptedFile != NULL)
                    {
                        int fileLength = decryptWithAES(encryptedData, length, currentAESKey, decryptedFile);
                        if (fileLength > 0)
                        {
                            char saveName[256];
                            sprintf(saveName, "ChatApp_%s", fileName); // dosya karışıklılığını engellemek için belki tarih eklenebilir
                            writeFile(saveName, decryptedFile, fileLength);
                        }
                        else
                        {
                            printf(RED "[-] " RESET "The file not decrypted.\n");
                        }
                        free(decryptedFile);
                    }
                    else
                    {
                        printf(RED "[-] " RESET "Memory error in decryptedFile.\n");
                    }
                    free(encryptedData);
                    printf("You: ");
                    fflush(stdout);
                    continue;
                }
            }
        }

        char *seperator = strchr(buffer, '|'); // TAG|DATA'yı parçalara böler
        if (seperator != NULL && chatReady == 0)
        {
            *seperator = '\0';
            char *tag = buffer;         // |'dan öncesi - pub key veya aes key
            char *data = seperator + 1; // |'dan sonrası - veri

            // TAG = PUBLIC KEY ise

            if (strcmp(tag, "PUBLICKEY") == 0)
            {
                printf(GREEN "[+] " RESET "The public key is taken from other client.\n"); // debug
                otherClientPublicKey = strToPEM(data);
                char *publicStr = getPublicKey(RSAKeyPair);

                if (strcmp(publicStr, data) > 0)
                {
                    printf(YELLOW "[*] " RESET "You are host, AES key sending to other client..\n");

                    RAND_bytes(currentAESKey, 32);   // AES üret
                    unsigned char encryptedKey[512]; // AES keyi RSA ile şifreleme
                    int length = encryptRSA(otherClientPublicKey, currentAESKey, 32, encryptedKey);
                    char *base64Key = encodeBase64(encryptedKey, length); // binary to base64

                    sendData(socket, "AESKEY", base64Key); // socket'e gönder
                    printf(GREEN "[+] " RESET "The connection is secured with end to end encryption now!\n");
                    chatReady = 1; // uçtan uca mesajlaşma hazır
                }
                else
                {
                    printf(YELLOW "[*] " RESET "Other client is host, AES key waiting other client..\n");
                    sendData(socket, "PUBLICKEY", publicStr);
                }
            }

            // TAG = AES KEY ise

            else if (strcmp(tag, "AESKEY") == 0)
            {
                printf(YELLOW "[*] " RESET "The aes key taken from other client. Decrypting...\n");
                int length;
                unsigned char *encryptData = decodeBase64(data, strlen(data), &length);

                decryptRSA(RSAKeyPair, encryptData, length, currentAESKey);
                printf(GREEN "[+] " RESET "The public key decrypted.\n");
                chatReady = 1;
            }
        }
        else if (chatActive == 1 && chatReady == 1)
        {
            if (strncmp(buffer, "FILE", 4) != 0 && strncmp(buffer, "PUBLICKEY", 9) != 0)
            {
                int length;
                unsigned char *cipherRaw = decodeBase64(buffer, strlen(buffer), &length);

                if (cipherRaw != NULL)
                {
                    int decryptLength = decryptWithAES(cipherRaw, length, currentAESKey, decrypedText);

                    if (decryptLength > 0)
                    {
                        if (strstr((char *)decrypedText, " left the chat") != NULL || strcmp((char *)decrypedText, "/exit") == 0)
                        {
                            printf("\r\033[K"); // boş you sil
                            printf(RED "[-] " RESET "Other client left the chat.");
                            chatActive = 0;
                            close(socket);
                            free(buffer);
                            return NULL;
                        }
                        printf("\r\033[K");
                        printf(YELLOW "Other Client:" RESET " %s \n", decrypedText);
                        printf("You: ");
                        fflush(stdout);
                    }
                    free(cipherRaw);
                }
            }
        }
    }
    free(buffer);
    return NULL;
}

int main()
{
    int clientSocket, clientConnect;
    struct sockaddr_in serverAddress;
    char buffer[1024];

    pthread_t recvThread;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket == -1)
    {
        printf(RED "[-]" RESET " Error: %s\n", strerror(errno));
    }
    printf(GREEN "[+]" RESET " Socket created successfully!\n");

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    // CONNECT

    clientConnect = connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
    if (clientConnect == -1)
    {
        printf(RED "[-]" RESET " The client not connected to the server! Error: %s\n", strerror(errno));
    }
    printf(GREEN "[+]" RESET " Connected to the server successfully!\n");

    // CREATE RSA KEY

    // printf("debug #1");
    RSAKeyPair = createRSAKeyPair();
    // printf("debug #2");
    if (RSAKeyPair == NULL)
    {
        printf(RED "[-] " RESET "RSA key not created.\n");
    }
    printf(GREEN "[+] " RESET "RSA key created.\n");

    // SEND AES KEY WITH RSA KEY

    char *publicStr = getPublicKey(RSAKeyPair);
    sendData(clientSocket, "PUBLICKEY", publicStr);
    printf(YELLOW "[*] " RESET "Public key sent, waiting other client.\n");

    // THREAD

    int createdThread = pthread_create(&recvThread, NULL, receiveMessage, (void *)&clientSocket);
    if (createdThread < 0)
    {
        printf(RED "[-]" RESET " The thread is not created.\n");
    }
    printf(GREEN "[+]" RESET " The thread created successfully!\n");

    while (1)
    {
        if (chatReady == 1)
            printf("You: ");

        fgets(buffer, 1024, stdin);

        if (chatActive == 0)
            break;

        if (chatReady == 0)
        {
            printf(YELLOW "[*] " RESET "Wait for end to end encryption connection.\n");
            continue;
        }

        buffer[strcspn(buffer, "\n")] = 0;

        // mesajlarda boşluk gönderilmesini engelleme için
        int justSpace = 1;
        for (int i = 0; i < strlen(buffer); i++)
        {
            if (buffer[i] != ' ')
            {
                justSpace = 0;
                break;
            }
        }

        if (strlen(buffer) > 0 && justSpace == 0)
        {
            unsigned char cipherText[1024];
            int cipherLength = encryptWithAES((unsigned char *)buffer, strlen(buffer), currentAESKey, cipherText);
            char *base64Text = encodeBase64(cipherText, cipherLength);

            // sohbetten çıkmak için - /exit

            if (strncmp(buffer, "/exit", 5) == 0)
            {
                send(clientSocket, base64Text, strlen(base64Text), 0);
                free(base64Text);
                printf("You left the chat.");
                close(clientSocket);
                break;
            }

            // sohbete resim/ses dosyası göndermek için - /file

            if (strncmp(buffer, "/file ", 6) == 0)
            {
                char *fileName = buffer + 6; // "/file " kısmını es geçmek için
                long fileSize;

                unsigned char *fileData = readFile(fileName, &fileSize);

                if (fileData != NULL)
                {
                    printf(GREEN "[+] " RESET "File %s(%ld byte) found.\n", fileName, fileSize);

                    unsigned char *fileCipherText = (unsigned char *)malloc(fileSize + 1024); // 32 90bytelık dosya da yetmedi
                    if (fileCipherText == NULL)
                    {
                        printf(RED "[-] " RESET "Memory error!\n");
                        free(fileData);
                        continue;
                    }

                    int cipherLenght = encryptWithAES(fileData, (int)fileSize, currentAESKey, fileCipherText);
                    char *base64Data = encodeBase64(fileCipherText, cipherLenght);
                    long packetSize = strlen(fileName) + strlen(base64Data) + 50; // 20 yetmedi 50 yapıldı
                    char *bigPacket = (char *)malloc(packetSize);                 // yer ayır

                    sprintf(bigPacket, "FILE|%s|%s", fileName, base64Data); // FILE|NAME|DATA

                    int sendFile = send(clientSocket, bigPacket, strlen(bigPacket), 0);
                    if (sendFile < 0)
                    {
                        printf(RED "[-] " RESET "File could not be sent!\n");
                    }
                    printf(GREEN "[+] " RESET "File sent successfully.\n");

                    free(fileData);
                    free(fileCipherText);
                    free(base64Data);
                    free(bigPacket);
                    free(base64Text);
                    continue;
                }
                else
                {
                    printf(RED "[-] " RESET "File could not be read!\n");
                    continue;
                }
            }

            send(clientSocket, base64Text, strlen(base64Text), 0);

            free(base64Text); // mesajı ramden silmek için
        }
    }
    return 0;
}