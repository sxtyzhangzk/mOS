#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct AVLNode
{
	struct AVLNode	*lchild, *rchild;
	intptr_t		 height;
	uintptr_t		 key;
	uintptr_t		 val;
} AVLNode;

void avl_insert(AVLNode *node, AVLNode **pRoot);
void avl_erase(AVLNode *node, AVLNode **pRoot);
AVLNode * avl_lower_bound(uintptr_t target, AVLNode *root);	//find the first node whose key >= target
AVLNode * avl_upper_bound(uintptr_t target, AVLNode *root);	//find the last node whose key <= target
AVLNode * avl_find(uintptr_t target, AVLNode *root);