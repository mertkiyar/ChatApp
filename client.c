#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "communicate.c"

#define PORT 6378
#define MAXSIZE 20 * 1024 * 1024 // şu anlık 15mb olarak yeterli gibi artırılabilir. Base64 ile birlikte 15 * 1.33=20

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"

int chatActive = 1; // exit için
int chatReady = 0;  // eşleşme için

EVP_PKEY *RSAKeyPair = NULL;
EVP_PKEY *otherClientPublicKey = NULL;
unsigned char currentAESKey[32];

void *receiveMessage(void *socket_desc)
{
    int socket = *(int *)socket_desc;
    // char buffer[4096]; resim ve ses dosyaları için çok küçük. 4kb mesajlara anca yetiyor
    char *sbuffer = (char *)malloc(MAXSIZE);

    if (sbuffer == NULL)
    {
        printf(RED "[-] " RESET "Memory allocation failed\n");
        return NULL;
    }
    sbuffer[0] = '\0'; // temizle
    long currentDataLenght = 0;

    char tempBuffer[4096]; // her bir buffer 4kb tasıyacak. kısaca 4kblik paketler halinde gönderilecek

    int readSize; // mesajdaki harf sayısı

    while ((readSize = recv(socket, tempBuffer, sizeof(tempBuffer), 0)) > 0) // 0'dan fazla harf varken
    {
        tempBuffer[readSize] = '\0';

        if (currentDataLenght + readSize >= MAXSIZE)
        {
            printf("\r\033[K");
            printf(RED "[-]" RESET " Buffer overflow! Max file size: 15MB\n");

            currentDataLenght = 0;
            sbuffer[0] = '\0';

            printf("You: ");
            fflush(stdout);

            continue;
        }

        memcpy(sbuffer + currentDataLenght, tempBuffer, readSize);
        currentDataLenght += readSize;
        sbuffer[currentDataLenght] = '\0';

        char *endTag = strstr(sbuffer, "|END");

        if (endTag == NULL)
            continue;

        *endTag = '\0';

        int msgStatus = receivePacket(socket, sbuffer);
        if (msgStatus == 0)
        {
            chatActive = 0;
            close(socket);
            break;
        }
        currentDataLenght = 0;
        sbuffer[0] = '\0';
    }
    free(sbuffer);
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
    serverAddress.sin_addr.s_addr = INADDR_ANY; // inet_addr("127.0.0.1");

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

    // SEND RSA PUBLIC KEY

    char *publicStr = getPublicKey(RSAKeyPair);
    sendKey(clientSocket, "PUBLICKEY", publicStr); // artık communicate.cden gönderiliyor
    printf(YELLOW "[*] " RESET "Public key sent, waiting other client.\n");

    // THREAD

    int createdThread = pthread_create(&recvThread, NULL, receiveMessage, (void *)&clientSocket);
    if (createdThread < 0)
    {
        printf(RED "[-]" RESET " The thread is not created.\n");
    }
    printf(GREEN "[+]" RESET " The thread created successfully!\n");

    while (chatActive)
    { // her zman çalışması yerine chat aktifken çalışması daha mantıklı(test et)
        if (chatReady == 1)
        {
            printf("You: ");
            fflush(stdout); // zorla ekrana yaz
        }
        else
        {
            printf(YELLOW "[*] " RESET "Wait for end to end encryption connection.\n");
        }

        fgets(buffer, 1024, stdin);
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

            // sohbetten çıkmak için - /exit

            if (strncmp(buffer, "/exit", 5) == 0)
            {
                sendText(clientSocket, "/exit");
                chatActive = 0;
                printf("You left the chat.");
                close(clientSocket);
                break;
            }

            // sohbete resim/ses dosyası göndermek için - /file

            else if (strncmp(buffer, "/file ", 6) == 0)
            {
                char *fileName = buffer + 6;      // "/file " kısmını es geçmek için
                sendFile(clientSocket, fileName); // artık communicate.c'de
                continue;
            }

            // sohbete mesaj yazıldığında

            sendText(clientSocket, buffer);
        }
    }
    return 0;
}