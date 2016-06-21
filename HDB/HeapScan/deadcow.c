#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define DEADCOWSIZE     20

/* Global Variable deadcow */
int* deadcow = NULL;

pid_t mypid = 0;

/* heap */
//09456000-09477000 rwxp 09456000 00:00 0          [heap]
// deadcow   = 0x9456008

void 
slaughter()
{
   int i = 0;
   int* ptr = NULL;

   fprintf(stdout, "&deadcow   = %p\n", &deadcow);

   deadcow = (int*)calloc(DEADCOWSIZE, sizeof(int));
   if(NULL==deadcow)
   {
      fprintf(stderr, "failed to create memory for dead cow\n");
      return;
   }
   
   fprintf(stdout, "&deadcow   = %p\n", &deadcow);
   fprintf(stdout, " deadcow   = %p\n", deadcow);
   fprintf(stdout, "*deadcow   = %x\n", *deadcow);

   ptr = deadcow;
   for(i=0;i<DEADCOWSIZE;i++)
   {
      *ptr = 0xDEADBEEF;
      ptr++;
   }

   fprintf(stdout, "&deadcow   = %p\n", &deadcow);
   fprintf(stdout, " deadcow   = %p\n", deadcow);
   fprintf(stdout, "*deadcow   = %x\n", *deadcow);
   fprintf(stdout, " ptr       = %p\n", ptr);
   //&ptr not interesting
   //*ptr is deadbeef

   return;
}

void
scan()
{
   //this is a trigger for HeapScan to look for "DEADBEEF";
   fprintf(stdout,"in scan()\n");
   fprintf(stdout,"freeing deadcow...\n");
   free(deadcow);
   deadcow=NULL;
   fprintf(stdout,"freed deadcow\n");
   //while(1){;}
   return;
}

int main(int argc, char* argv[])
{
   fflush(stdout);
   mypid = getpid();
   fprintf(stdout, "\ndeadcow.c: my process id is: %d\n", mypid);

   slaughter();
   scan();
   return 0;
}
