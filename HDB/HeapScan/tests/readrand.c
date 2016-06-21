#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define LIMIT   4096

/**
 * Open and read /dev/urandom, filling a buffer of size LIMIT. 
 * Repeat forever.
 *
 */
int
main(int argc, 
     char* argv[])
{
  long long current_run = 0L;
  char* buffer = NULL;
  unsigned char c;
  int x = 0;
  FILE* fin=NULL;
  char* itr=NULL;
  int i = 0;

  fin = fopen("/dev/urandom","r");
  if(NULL==fin)
  {
    perror("main():");
    return -1;
  }

  buffer = (char*)calloc(LIMIT, sizeof(char));
  if(NULL==buffer)
  {
    perror("main():");
    return -2;
  }

  for(;;)
  {
    itr = buffer;
    for(i=0;i<LIMIT;i++)
    {
      x = fgetc(fin);
      c = (unsigned char)x;
      *itr=c;
      itr++;
    }
    current_run++;
  }

  free(buffer);
  buffer=NULL;
  if(EOF!=fclose(fin))
    perror("exiting main():");
  fin=NULL;

  return 0;
}
