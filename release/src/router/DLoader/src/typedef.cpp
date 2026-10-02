#include "typedef.h"
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

int is_dir(char * filename)
{
    struct stat buf;
    int ret = stat(filename,&buf);
    if(0 == ret)
    {
        if(buf.st_mode & S_IFDIR)
        {
            //printf("%s is folder\n",filename);
            return 0;
        }
        else
        {
            //printf("%s is file\n",filename);
            return 1;
        }
    }
    return -1;
}


int delete_dir(const char * dirname)
{
    char chBuf[256]= {0};
    DIR * dir = NULL;
    struct dirent *ptr;
    int ret = 0;
    dir = opendir(dirname);
    if(NULL == dir)
    {
        return -1;
    }
    while((ptr = readdir(dir)) != NULL)
    {
        ret = strcmp(ptr->d_name, ".");
        if(0 == ret)
        {
                continue;
        }
        ret = strcmp(ptr->d_name, "..");
        if(0 == ret)
        {
            continue;
        }
        snprintf(chBuf, 256, "%s/%s", dirname, ptr->d_name);
        ret = is_dir(chBuf);

        if(0 == ret)
        {
            //printf("%s is dir\n", chBuf);
            ret = delete_dir(chBuf);
            if(0 != ret)
            {
                return -1;
            }
        }
        else if(1 == ret)
        {
            //printf("%s is file\n", chBuf);
            ret = remove(chBuf);
            if(0 != ret)
            {
                 return -1;
            }
        }
    }

    (void)closedir(dir);

    ret = remove(dirname);
    if(0 != ret)
    {
        return -1;
    }
    return 0;
}

unsigned long GetTickCount()
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}