#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

typedef struct
{
    char file_path[FILENAME_MAX];
    char type_hash[10];
    unsigned char checksum[65];
} FILE_DATA;

int main(int argc, char * argv[])
{
    FILE * task;
    FILE * work;
    FILE_DATA file_data;
    struct stat stat_file;
    char * taskbuf;
    char * pointer;
    char * workbuf;
    char str[256];
    unsigned char hashbuf[65];
    unsigned char checksum[33];
    char * ch;
    size_t size_file, work_size;

    if ( (task = fopen(argv[1], "rb")) == NULL )
    {
        printf("task file is not opened!\n");
        return -1;
    }
    stat(argv[1], &stat_file);
    size_file = (unsigned)stat_file.st_size;


    if ( size_file == 0 )
    {
        printf("Input file is empty\n");
        return -1;
    }

    taskbuf = (char*)calloc(size_file + 1, sizeof(char));

    while( (ch = fgets(str, sizeof(str), task)) != NULL )
    {
        for ( int i = 0; i < strlen(str); i++ )
        {
            if ( str[i] == '\n' )
                str[i - 1] = '\0';
        }
        pointer = strtok(str, " ");
        while ( pointer != NULL )
        {
            strcpy(file_data.file_path, pointer);
            sprintf(file_data.file_path, "%s\%s", argv[2], pointer);

            pointer = strtok(NULL, " ");
            strcpy(file_data.type_hash, pointer);

            pointer = strtok(NULL, " ");
            strcpy((char*)file_data.checksum, pointer);

            pointer = strtok(NULL, " ");
        }

        if ( (work = fopen(file_data.file_path, "rb")) == NULL )
        {
            printf("%s NOT FOUND", file_data.file_path);
            continue;
        }

        stat(file_data.file_path, &stat_file);
        work_size = (unsigned)stat_file.st_size;
        workbuf = (char*)calloc(work_size + 1, sizeof(char));
        fread(workbuf, sizeof(char), work_size, work);

        if ( strcmp(file_data.type_hash, "md5") == 0 )
        {
            MD5((unsigned char *)workbuf, work_size, checksum);
            for ( int i = 0, j = 0; i < 16; i++, j += 2 )
                sprintf((char*)(hashbuf + j), "%02x", checksum[i]);

            if ( strcmp(file_data.checksum, hashbuf) == 0 )
                printf("%s OK\n", file_data.file_path);
            else
                printf("%s FAIL\n", file_data.file_path);
        }
        else if ( strcmp(file_data.type_hash, "sha1") == 0 )
        {
            SHA1((unsigned char *)workbuf, work_size, checksum);
            for ( int i = 0, j = 0; i < 20; i++, j += 2 )
                sprintf((char*)(hashbuf + j), "%02x", checksum[i]);

            if ( strcmp(file_data.checksum, hashbuf) == 0 )
                printf("%s OK\n", file_data.file_path);
            else
                printf("%s FAIL\n", file_data.file_path);
        }
        else if ( strcmp(file_data.type_hash, "sha256") == 0 )
        {
            SHA256((unsigned char *)workbuf, work_size, checksum);

            for ( int i = 0, j = 0; i < 32; i++, j += 2 )
                sprintf((char*)(hashbuf + j), "%02x", checksum[i]);

            if ( strcmp(file_data.checksum, hashbuf) == 0 )
                printf("%s OK\n", file_data.file_path);
            else
                printf("%s FAIL\n", file_data.file_path);
        }


        fclose(work);
        free(workbuf);
    }

    fclose(task);
    free(taskbuf);

    return 0;
}
