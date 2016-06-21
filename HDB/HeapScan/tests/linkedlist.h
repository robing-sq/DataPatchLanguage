#ifndef _LINKEDLIST_H_
#define _LINKEDLIST_H_

#define MAX_TO_CREATE   100

typedef struct _stack_node
{
  char* name;
  int name_length;
  long age;
  struct _stack_node* _next;
} StackNode;

void      push(StackNode* n);
StackNode peek();
StackNode peek_at(int i);
StackNode pop();

#endif
