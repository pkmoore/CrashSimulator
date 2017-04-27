#include <dirent.h>
#include <stdio.h>
#include <string.h>

int main(){
    DIR* dirFile = opendir( "." );
    struct dirent* hFile;
    int i;
    int c;
     FILE *fp;
    fp = fopen("readdir.out", "w+");
    if ( dirFile ) 
    {
    while (( hFile = readdir( dirFile )) != NULL ) 
    {
        for(i = 0; i < 4; i++) {
            c = *(((unsigned char*)hFile + i));
            fprintf(fp, "%02x ", c);
        }
        fprintf(fp, "| ");
        for(i = 4; i < strlen(hFile->d_name); i++){
            c = *(((unsigned char*)hFile + i));
            fprintf(fp, "%02x ", c);
        }
        fprintf(fp, "\n");
        fflush(fp);
    }
    fclose(fp);
    closedir( dirFile );
 }
}
