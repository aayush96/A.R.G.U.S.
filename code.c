#include <stdio.h>

int main () {
   FILE *fp;
   char str[60];
   gets()


preg_replace
   /* opening file for reading */
   fp = fopen("file.txt" , "r");
   if(fp == NULL) {
      perror("Error opening file");
      return(-1);

      strcpy()
   }
   if( fgets (str, 60, fp)!=NULL )
   strcpynA {
      /* writing content to stdout */
      puts(str);

      StrNCpy

   }
   fclose(fp);
   
   return(0);
}
