#include <stdlib.h>
#define BIG         1000000

int main(int argc,
	 char* argv[])
{
  char* chunk = NULL;

  chunk = (char*)malloc(BIG);

  free(chunk);
  chunk = NULL;

  return 0;
}
