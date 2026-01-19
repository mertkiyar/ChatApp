#include <stdio.h>
#include <stdlib.h>

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"

long getFileSize(const char *fileName)
{
    FILE *file = fopen(fileName, "rb"); // rb = read binary

    if (file == NULL)
        return -1;

    fseek(file, 0, SEEK_END); // baştan sona kadar kaç byte olduğunu bul
    long fileSize = ftell(file);
    fclose(file);
    return fileSize;
}

unsigned char *readFile(const char *fileName, long *fileSize)
{
    *fileSize = getFileSize(fileName);
    if (*fileSize == -1)
        return NULL;

    FILE *file = fopen(fileName, "rb");
    if (file == NULL)
        return NULL;

    unsigned char *data = (unsigned char *)malloc(*fileSize + 1); // fileSize boyutuna göre alan ayırır
    if (data == 0)
    {
        fclose(file);
        return NULL;
    }

    fread(data, 1, *fileSize, file);
    data[*fileSize] = '\0';

    fclose(file);
    return data;
}

void writeFile(const char *fileName, unsigned char *data, int fileSize)
{
    FILE *file = fopen(fileName, "wb"); // write binary
    if (file)
    {
        fwrite(data, 1, fileSize, file);
        fclose(file);
        printf(GREEN "[+] " RESET "The file %s saved.\n", fileName);
    }
    else
    {
        printf(RED "[-] " RESET "The file not saved.\n");
    }
}