#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "crypt.c"

#define PORT 6378

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"

int chatActive = 1;
int chatReady = 0;

EVP_PKEY *RSAKey = NULL;
EVP_PKEY *otherClientPublicKey = NULL;
unsigned char currentAESKey[32];

void sendData(int socket, char *tag, char *data)
{
    char packet[1024];
    sprintf(packet, "%s:%s", tag, data);
    send(socket, packet, strlen(packet), 0);
}

void *receiveMessage(void *socket_desc)
{
    int socket = *(int *)socket_desc;
    char buffer[4096]; // artırılabilir fakat düşürme şifreleme için sorun olusabilir
    int readSize;      // mesajdaki harf sayısı

    char *tag;
    char *data;
    unsigned char decrypedText[1024];

    while ((readSize = recv(socket, buffer, 4096, 0)) > 0) // 0'dan fazla harf varken
    {
        buffer[readSize] = '\0';

        char *seperator = strchr(buffer, ':'); // şu anlık : ile key ayrılıyor sonradan - veya / yapılabilir
        if (seperator != NULL && chatReady == 0)
        {
            *seperator = '\0';
            tag = buffer;         // :'dan öncesi - pub key veya aes key
            data = seperator + 1; // :'dan sonrası - veri

            //
            if (strcmp(tag, "PUBLICKEY") == 0)
            {
                printf(GREEN "[+] " RESET "The public key is taken from other client.\n"); // debug
                otherClientPublicKey = strToPEM(data);
                char *publicStr = getPublicKey(RSAKey);

                if (strcmp(publicStr, data) > 0)
                {
                    printf(YELLOW "[*] " RESET "You are host, AES key sending to other client..\n");

                    RAND_bytes(currentAESKey, 32); // AES üret

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
            else if (strcmp(tag, "AESKEY") == 0)
            {
                printf(YELLOW "[*] " RESET "The aes key taken from other client. Decrypting...\n");
                int length;
                unsigned char *encryptData = decodeBase64(data, strlen(data), &length);

                decryptRSA(RSAKey, encryptData, length, currentAESKey); // Private key ile public key çözülür

                printf(GREEN "[+] " RESET "The public key decrypted.\n");
                chatReady = 1;
            }
        }
        else
        {
            if (chatActive == 1)
            {
                int length;
                unsigned char *cipherRaw = decodeBase64(buffer, strlen(buffer), &length);
                decryptWithAES(cipherRaw, length, currentAESKey, decrypedText);

                if (strstr((char *)decrypedText, " left the chat") != NULL || strcmp((char *)decrypedText, "/exit") == 0)
                {
                    printf("\r\033[K"); // boş you sil
                    printf(RED "[-] " RESET "Other client left the chat.");
                    chatActive = 0;
                    close(socket);
                    return NULL;
                }
                printf("\r\033[K");
                printf(YELLOW "Other Client:" RESET " %s \n", decrypedText);
                printf("You: ");
                fflush(stdout);
            }
        }
    }
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
    RSAKey = createRSAKey();
    // printf("debug #2");
    if (RSAKey == NULL)
    {
        printf(RED "[-] " RESET "RSA key not created.\n");
    }
    printf(GREEN "[+] " RESET "RSA key created.\n");

    // SEND AES KEY WITH RSA KEY

    char *publicStr = getPublicKey(RSAKey);
    sendData(clientSocket, "PUBLICKEY", publicStr);
    printf(YELLOW "[*] " RESET "Public key sent, waiting other client.\n");

    // THREAD

    int createdThread = pthread_create(&recvThread, NULL, receiveMessage, (void *)&clientSocket);
    if (createdThread < 0)
    {
        printf(RED "[-]" RESET " Error: The thread is not created.\n");
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
            printf(YELLOW "[*] " RESET "Wait for end to end encryption connection.");
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
            if (strncmp(buffer, "/exit", 5) == 0) // sohbetten çıkmak için
            {
                send(clientSocket, base64Text, strlen(base64Text), 0);
                free(base64Text);
                printf("You left the chat.");
                close(clientSocket);
                break;
            }

            send(clientSocket, base64Text, strlen(base64Text), 0);

            free(base64Text); // mesajı silmek için
        }
    }
}