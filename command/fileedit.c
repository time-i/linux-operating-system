#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <malloc.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

void printdir(char *dir, int depth)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

    if((dp = opendir(dir)) == NULL) {
        fprintf(stderr, "connot open directory: %s\n",dir);
        return ;
    }
    chdir(dir); //the same as comand"cd"
    while((entry = readdir(dp)) != NULL) {
        stat(entry->d_name, &statbuf);  //lstat(entry->d_name, &statbuf);
        if(S_ISDIR(statbuf.st_mode)) {
            //Found a directory, but ignore. and ..
            if(strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0)
                continue;
            printf("%*s%s/\n", depth, "", entry->d_name);
            //Recurse at a new indent level
            printdir(entry->d_name, depth + 4);
        }
        //else printf("%*s%s\n", depth, "", entry->d_name);
    }
    chdir("..");
    closedir(dp);
}


int GetFileNamesInDir(char *DirPath,char *FileExtName,char FileNames[][128],int *FileNum,int MaxFileNum)
{
    DIR *dir;
    struct dirent *ptr;
 
    if ((dir=opendir(DirPath)) == NULL)
    {
        perror("Open dir error...");
        exit(1);
    }
    
    char *CurFileExtName = NULL;
    while ((ptr=readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0) ///current dir OR parrent dir
            continue;//跳过.和..目录
        else if(ptr->d_type == 8)    ///d_type=8对应file
        {  
            CurFileExtName = rindex(ptr->d_name, '.');//char *rindex(const char *s, int c);rindex()用来找出参数s 字符串中最后一个出现的参数c 地址，然后将该字符出现的地址返回。字符串结束字符(NULL)也视为字符串一部分。
            if(CurFileExtName!=NULL&& strcmp(CurFileExtName,FileExtName) == 0)
            {  
                if(*FileNum<MaxFileNum)
                {
                   memcpy(FileNames[(*FileNum)++],ptr->d_name,sizeof(ptr->d_name)); 
                   //printf("CurFilePath=%s/%s\n",DirPath,ptr->d_name);
                }
                
            }     
        }     
    }
    closedir(dir);
 
    return 1;
}


int find(){
    char *DirPath="./";
    char *FileExtName=".c";
    char FileNames[1000][128];
    int MaxFileNum=1000;
    int FileNum=0;
    GetFileNamesInDir(DirPath,FileExtName,FileNames,&FileNum,MaxFileNum);
    printf("########Find include %s suffix FileNum=%d########\n",FileExtName,FileNum);
    for(int i=0;i<FileNum;i++)
    {
         printf("CurFilePath=%s\n",FileNames[i]);
    }

    char filename[10] = {0};
    scanf("%s", filename);

    printf("%s", filename);
    int fd = open(filename, O_RDWR | O_APPEND);
    if(fd == -1) {
    printf("error");
    return -1;
    }

    char buf[100];
    memset(buf, 0 , sizeof(buf));
    strcpy(buf, "printf('hhhhh')");
    write(fd, buf, strlen(buf));
    return 0;
}


int main(int argc, char *argv[])
{
    char *topdir, pwd[] = "..";
    if(argc != 2)
        topdir = pwd;
    else
        topdir = argv[1];

    printf("Directory scan of %s\n", topdir);
    printdir(topdir, 0);
    printf("done.\n");
    
    find();
    return 0;
}

