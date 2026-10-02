#include <stdlib.h>
#include <stdio.h>
#include <queue_list.h>


void initQueue(QUEUE *q)
{
	q->size = 0;
	q->front = q->rear = NULL;
}

int queueIsEmpty(QUEUE *q) 
{
	return q->front == NULL;
}

int queueLength(QUEUE *q) 
{
	return q->size;
}

void pushQueue(QUEUE *q, void* y) 
{
	ITEM * x = (ITEM *) malloc(sizeof(ITEM));
	x->data = y;
	x->next = NULL;
	if (q->front == NULL)
		q->front = x;
	else
		q->rear->next = x;
	q->rear = x;
	q->size++;
}

void* popQueue(QUEUE *q) 
{
	ITEM * x = q->front;
	if (!x) return NULL;
	void* d = x->data;
	q->front = x->next;
	if (q->front == NULL)
		q->rear = NULL;
	q->size--;
	free(x);
	return d;
}




