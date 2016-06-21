#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "linkedlist.h"

StackNode* head;
unsigned long stack_size;

void
push(StackNode* n)
{
  if(NULL==head)
  {
    head = n;
    head->_next = NULL;
  }else{
    n->_next = head;
    head = n;
  }
  stack_size++;
}

StackNode peek()
{
  StackNode s;
  if(stack_size<=0)
    return s;
  return s;
}

StackNode peek_at(int i)
{
  StackNode s;
  if(stack_size<=0)
    return s;
  return s;
}

StackNode 
pop()
{
  StackNode s;
  StackNode* tmp = NULL;

  if(stack_size<=0)
    return s;

  tmp = head;
  head = head->_next;

  s.name = tmp->name;
  s.name_length = tmp->name_length;
  s.age = tmp->age;
  s._next = NULL;

  free(tmp);
  tmp = NULL;
  stack_size--;
  return s;
}

static void
peek_node()
{
  StackNode s;
  if(stack_size<=0)
    return;
  s = peek();
  return;
}

static void
peek_at_node()
{
  StackNode s;
  int r = 0; 
  if(stack_size<=0)
    return;
  r = random() % stack_size;
  s = peek_at(r);
}

static void
delete_nodes(int howmany)
{
  long i = 0;
  for(i=0;i<howmany;i++)
  {
    pop();
  }
}

static void
create_nodes(int howmany)
{
  long i = 0;
  long rage = 0;
  StackNode* s = NULL;
  for(i=0;i<howmany;i++)
  {
    rage = random() % 100;
    s = (StackNode*)malloc(sizeof(StackNode));
    if(NULL==s)
    {
      fprintf(stderr,
	      "out of memory for new nodes\n");
      return;
    }
    s->name = "michael";
    s->name_length = strlen(s->name);
    s->age = rage;
    s->_next = NULL;
    push(s);
  }
}

static void
execute()
{
  long num_to_create = 0;
  long num_to_delete = 0;
  long random_mod = 0;

  for(;;)
  {
    num_to_create = random() % MAX_TO_CREATE;
    if(0!=stack_size)
    {
      num_to_delete = random() % stack_size;
      random_mod = random() % 4; //operation selection
    }else{
      random_mod = 0;
      num_to_delete = 0;
    }

    switch(random_mod)
    {
    case 0:
      fprintf(stdout,
	      "creating %ld nodes\n",
	      num_to_create);
      create_nodes(num_to_create);
      break;
    case 1:
      fprintf(stdout,
	      "deleting %ld nodes\n",
	      num_to_delete);
      delete_nodes(num_to_delete);
      break;
    case 2:
      peek_node();
      break;
    case 3:
      peek_at_node();
      break;
    default:
      fprintf(stderr,
	      "should not happen\n");
      break;
    }      
  }
}

/**
 * This program randomly creates a number of StackNodes
 * at varying times during runtime and basically does a
 * number on the heap.
 */
int main(int argc,
	 char* argv[])
{
  srandom(time(NULL));
  execute();
  return 0;
}
