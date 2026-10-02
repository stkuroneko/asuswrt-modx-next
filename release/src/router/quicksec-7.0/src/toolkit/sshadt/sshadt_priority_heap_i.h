/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_priority_heap_i.h
*/

#ifndef SSH_ADT_PRIORITY_HEAP_I_H_INCLUDED
#define SSH_ADT_PRIORITY_HEAP_I_H_INCLUDED

#include "sshadt.h"

typedef struct SshADTPriorityHeapNodeRec {
  uint32_t height;
  struct SshADTPriorityHeapNodeRec *left, *right, *parent;
} SshADTPriorityHeapNodeStruct, *SshADTPriorityHeapNode;

typedef struct {
  void *object;
  SshADTPriorityHeapNodeStruct n;
} SshADTPriorityHeapENodeStruct, *SshADTPriorityHeapENode;

typedef struct {
  SshADTPriorityHeapNode min;
} SshADTPriorityHeapRootStruct;


#endif /* SSH_ADT_PRIORITY_HEAP_I_H_INCLUDED */
