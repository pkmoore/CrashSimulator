#include <dirent.h>
#include <stdio.h>
#include <string.h>

int main(){
    DIR* dirFile = opendir( "." );
    struct dirent* hFile;
    if ( dirFile ) 
    {
    while (( hFile = readdir( dirFile )) != NULL ) 
    {
        printf("d_name: %s\n", hFile->d_name);
        printf("d_ino: %llu\n", (unsigned long long)hFile->d_ino);
    }
  closedir( dirFile );
 }
}
