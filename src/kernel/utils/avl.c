#include <utils/avl.h>
#include <arch/common/fault.h>
#include <stdbool.h>

static inline intptr_t height(const AVLNode *node)
{
	if (!node)
		return -1;
	return node->height;
}

static inline intptr_t balance(const AVLNode *node)
{
	intptr_t hl = height(node->lchild);
	intptr_t hr = height(node->rchild);
	return hl - hr;
}

static inline void update_height(AVLNode *node)
{
	intptr_t hl = height(node->lchild);
	intptr_t hr = height(node->rchild);
	node->height = hl > hr ? hl + 1 : hr + 1;
}

static inline bool less_node(const AVLNode *lhs, const AVLNode *rhs)
{
	if (lhs->key == rhs->key)
		return lhs < rhs;
	return lhs->key < rhs->key;
}

static inline void rotate_l(AVLNode **pNode)
{
	AVLNode *o = *pNode;
	AVLNode *k = o->rchild;
	kassert(k);

	o->rchild = k->lchild;
	k->lchild = o;
	update_height(o);
	update_height(k);
	*pNode = k;
}

static inline void rotate_r(AVLNode **pNode)
{
	AVLNode *o = *pNode;
	AVLNode *k = o->lchild;
	kassert(k);

	o->lchild = k->rchild;
	k->rchild = o;
	update_height(o);
	update_height(k);
	*pNode = k;
}

static inline void LL(AVLNode **pNode)
{
	rotate_r(pNode);
}

static inline void RR(AVLNode **pNode)
{
	rotate_l(pNode);
}

static inline void LR(AVLNode **pNode)
{
	rotate_l(&(*pNode)->lchild);
	rotate_r(pNode);
}

static inline void RL(AVLNode **pNode)
{
	rotate_r(&(*pNode)->rchild);
	rotate_l(pNode);
}

void avl_insert(AVLNode *node, AVLNode **pRoot)
{
	if (!*pRoot)
	{
		node->height = 0;
		node->lchild = node->rchild = NULL;
		*pRoot = node;
		return;
	}
	AVLNode *root = *pRoot;
	if (less_node(node, root))
	{
		avl_insert(node, &root->lchild);
		update_height(root->lchild);
		if (height(root->lchild) - height(root->rchild) == 2)
		{
			if (less_node(node, root->lchild))
				LL(pRoot);
			else
				LR(pRoot);
		}
	}
	else
	{
		avl_insert(node, &root->rchild);
		update_height(root->rchild);
		if (height(root->rchild) - height(root->lchild) == 2)
		{
			if (less_node(node, root->rchild))
				RL(pRoot);
			else
				RR(pRoot);
		}
	}
}

void avl_erase(AVLNode *node, AVLNode **pRoot)
{
	kassert(*pRoot);
	AVLNode *root = *pRoot;
	if (root == node)
	{
		if (root->lchild && root->rchild)
		{
			AVLNode *k = avl_lower_bound(root->key, root->rchild);
			avl_erase(k, &root->rchild);
			k->lchild = root->lchild;
			k->rchild = root->rchild;
			update_height(k);
			root = *pRoot = k;

			node->lchild = NULL;
			node->rchild = NULL;
			node->height = 0;
		}
		else
		{
			if (root->lchild)
				root = *pRoot = root->lchild;
			else if (root->rchild)
				root = *pRoot = root->rchild;
			else
				root = *pRoot = NULL;
			node->lchild = NULL;
			node->rchild = NULL;
			node->height = 0;
			return;
		}
	}
	else if (less_node(node, root))
	{
		avl_erase(node, &root->lchild);
		update_height(root);
	}
	else
	{
		avl_erase(node, &root->rchild);
		update_height(root);
	}

	//update_height(root);

	intptr_t hl = height(root->lchild);
	intptr_t hr = height(root->rchild);

	if (hl - hr == 2)
	{
		if (balance(root->lchild) >= 0)
			rotate_r(pRoot);
		else
			LR(pRoot);
	}
	else if (hr - hl == 2)
	{
		if (balance(root->rchild) <= 0)
			rotate_l(pRoot);
		else
			RL(pRoot);
	}
	//root = *pRoot;
	//update_height(root);
}

AVLNode * avl_lower_bound(uintptr_t target, AVLNode *root)
{
	if (!root)
		return NULL;
	if (target > root->key)
		return avl_lower_bound(target, root->rchild);
	AVLNode *k = avl_lower_bound(target, root->lchild);
	if (k)
		return k;
	return root;
}

AVLNode * avl_upper_bound(uintptr_t target, AVLNode *root)
{
	if (!root)
		return NULL;
	if (target < root->key)
		return avl_upper_bound(target, root->lchild);
	AVLNode *k = avl_upper_bound(target, root->rchild);
	if (k)
		return k;
	return root;
}

AVLNode * avl_find(uintptr_t target, AVLNode *root)
{
	if (!root)
		return NULL;
	if (target == root->key)
		return root;
	if (target < root->key)
		return avl_find(target, root->lchild);
	else
		return avl_find(target, root->rchild);
}