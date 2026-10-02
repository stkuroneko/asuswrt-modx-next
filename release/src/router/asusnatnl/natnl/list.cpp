/*
 * Project: udptunnel
 * File: list.c
 *
 * Copyright (C) 2009 Daniel Meekins
 * Contact: dmeekins - gmail
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <list.h>

#include <pj/log.h>
#include <pjlib.h>

#define THIS_FILE "list.c"

extern PJ_DEF(pj_pool_t *) pjsip_get_app_pool(int inst_id);
extern PJ_DEF(pj_pool_t *) pjsip_get_stream_pool(int inst_id, int call_id);
extern PJ_DEF(pj_status_t) pj_mutex_create_simple( pj_pool_t *pool, const char *name, pj_mutex_t **mutex );
extern PJ_DEF(pj_status_t) pj_mutex_lock(pj_mutex_t *mutex);
extern PJ_DEF(pj_status_t) pj_mutex_unlock(pj_mutex_t *mutex);
extern PJ_DEF(pj_status_t) pj_mutex_destroy(pj_mutex_t *mutex);


natnl_list_t *natnl_list_create(int inst_id, int call_id, int obj_sz,
					int (*obj_cmp)(const void *, const void *, size_t),
					void* (*obj_copy)(void *, const void *, size_t),
					void (*obj_free)(void **), int sort)
{
	return natnl_list_create2(inst_id, call_id, obj_sz, obj_cmp, obj_copy, obj_free, sort, LIST_INIT_SIZE);
}

void mem_free(void **p)
{
	if (*p) {
		free(*p);
		*p = NULL;
	}
}

/*
 * Allocates and initializes a new list type to hold objects of obj_sz bytes,
 * and uses the cmp, copy, and free functions. If any of the function pointers
 * are NULL, they will be set to memcmp, memcpy, or free.
 */
natnl_list_t *natnl_list_create2(int inst_id, int call_id, int obj_sz,
                    int (*obj_cmp)(const void *, const void *, size_t),
                    void* (*obj_copy)(void *, const void *, size_t),
                    void (*obj_free)(void **), int sort, int init_size)
{
    natnl_list_t *new_list;
	pj_status_t status = PJ_SUCCESS;

    new_list = (natnl_list_t *)malloc(sizeof(*new_list));
    if(!new_list)
        return NULL;

    new_list->obj_arr = (void **)malloc(init_size * sizeof(void *));
    if(!new_list->obj_arr)
    {
        free(new_list);
        return NULL;
    }

    new_list->obj_sz = obj_sz;
    new_list->num_objs = 0;
    new_list->length = init_size;
    new_list->sort = sort;
    new_list->obj_cmp = obj_cmp ? obj_cmp : &memcmp;
    new_list->obj_copy = obj_copy ? obj_copy : &memcpy;
    new_list->obj_free = obj_free ? obj_free : &mem_free;

	if (inst_id > 0) {
		pj_pool_t *pool = (call_id < 0) ? pjsip_get_app_pool(inst_id) : pjsip_get_stream_pool(inst_id, call_id);
		if (!pool)
			return NULL;

#ifdef USE_DISCONNECT_LOCK
		// +Roger - Create Disconnect Mutex
		status = pj_mutex_create_simple(pool, NULL, &new_list->disconn_lock);
		if (status != PJ_SUCCESS){
			PJ_LOG(4, (THIS_FILE, "list_create() pj_mutex_create_simple FAILED!"));
			//pj_mutex_destroy(new_list->dissconn_lock);
			new_list->disconn_lock = NULL;
		}
#endif
	} else {
#ifdef USE_DISCONNECT_LOCK
		new_list->disconn_lock = NULL;
#endif
	}

    return new_list;
}

void *natnl_list_add(natnl_list_t *list, void *obj, int copy)
{
	return natnl_list_add2(list, obj, copy, 1);
}

/*
 * Inserts a new object into the list in sorted order (if set). If specified,
 * makes a deep copy of the object and returns a pointer to that new object if
 * obj wasn't already in the list, or a pointer to the object already in the
 * list.
 */
void *natnl_list_add2(natnl_list_t *list, void *obj, int copy, int check_exists)
{
    void *o;
    void **new_arr;
    void *temp;
    int i;

	if (check_exists)
	{
		/* Check if obj is already in the list, and return it if so */
		o = natnl_list_get(list, obj);
		if(o) {
			return o;
		}
	}

    if(copy == 1)
    {
        o = malloc(list->obj_sz);
        if(o == NULL) {
            return NULL;
        }

        list->obj_copy(o, obj, list->obj_sz);
    }
    else
    {
        o = obj;
    }

    /* Resize the object array if needed, doubling the size */
    if(list->num_objs == list->length)
    {
        new_arr = (void **)realloc(list->obj_arr, list->length * 2 * sizeof(void **));
        if(!new_arr)
        {
            list->obj_free(&o);
            return NULL;
        }

        list->obj_arr = new_arr;
        list->length *= 2;
    }

    /* Insert new object at end of array */
    list->obj_arr[list->num_objs++] = o;

    if(list->sort == 1)
    {
        /* Move object up in array until list is sorted again */
        for(i = list->num_objs-1; i > 0; i--)
        {
            if(list->obj_cmp(list->obj_arr[i-1], list->obj_arr[i],
                             list->obj_sz) > 0)
            {
                temp = list->obj_arr[i-1];
                list->obj_arr[i-1] = list->obj_arr[i];
                list->obj_arr[i] = temp;
            }
            else
                break; /* since was sorted before, just need to go this far */
        }
    }
    
    return o;
}

/*
 * Returns a pointer to the object that matches the one passed, or NULL if
 * one wasn't found. Does a simple linear search for now.
 */
void *natnl_list_get(natnl_list_t *list, void *obj)
{

    int i;

    i = natnl_list_get_index(list, obj);
    if(i == -1) {
        return NULL;
    }

    void **ret_obj = (void **)list->obj_arr[i];
    return ret_obj;
}

/*
 * Returns a pointer to the object at position i in the list or NULL if i is
 * out of bounds.
 */
void *natnl_list_get_at(natnl_list_t *list, int i)
{
    //acquire_list_lock(list, "list_get_at()=>rentered");
    if(i >= list->num_objs || i < 0) {
        //release_list_lock(list, "list_get_at()=>list out of bound");
        return NULL;
    }

    void **obj = (void **)list->obj_arr[i];
    //release_list_lock(list, "list_get_at()=>leave normally");
    return obj;
}

/*
 * Gets the index of object that's equal to the passed object.
 */
int natnl_list_get_index(natnl_list_t *list, void *obj)
{
    int i;

    for(i = 0; i < list->num_objs; i++)
    {
        if(list->obj_arr[i] != NULL && obj != NULL && //DEAN added
           list->obj_cmp(list->obj_arr[i], obj, list->obj_sz) == 0) {
            return i;
        }
    }
    return -1;
}

/*
 * Does a deep copy of src into a newly created list, and returns a pointer to
 * the new list.
 */
natnl_list_t *natnl_list_copy(int inst_id, int call_id, natnl_list_t *src)
{
    natnl_list_t *dst;
    int i;
	pj_status_t status;
    
    dst = (natnl_list_t *)malloc(sizeof(*dst));
    if(!dst)
        return NULL;

    memcpy(dst, src, sizeof(*src));

    /* Create the pointer array */
    dst->obj_arr = (void **)malloc(sizeof(void *) * src->length);
    if(!dst->obj_arr)
    {
        free(dst);
        return NULL;
    }

    /* Make copies of all the objects in the src array */
    for(i = 0; i < src->num_objs; i++)
    {
        dst->obj_arr[i] = malloc(dst->obj_sz);
        if(!dst->obj_arr[i])
        {
            dst->num_objs = i; /* so only will free objs up to this point */
            natnl_list_free(&dst);
            return NULL;
        }

        dst->obj_copy(dst->obj_arr[i], src->obj_arr[i], dst->obj_sz);
	}
	
	if (inst_id > 0) {
		pj_pool_t *pool = (call_id < 0) ? pjsip_get_app_pool(inst_id) : pjsip_get_stream_pool(inst_id, call_id);
		if (!pool)
			return NULL;

#ifdef USE_DISCONNECT_LOCK
		// +Roger - Create Disconnect Mutex
		status = pj_mutex_create_simple(pool, NULL, &dst->disconn_lock);
		if (status != PJ_SUCCESS){
			PJ_LOG(4, (THIS_FILE, "list_create() pj_mutex_create_simple FAILED!"));
			//pj_mutex_destroy(dst->dissconn_lock);
			dst->disconn_lock = NULL;
		}
#endif
	}

    return dst;
}

/*
 * Calls a function 'action', passing each object in the list to it, one at
 * a time.
 */
void natnl_list_action(natnl_list_t *list, void (*action)(void *))
{
    int i;

    for(i = 0; i < list->num_objs; i++)
        action(list->obj_arr[i]);
}

/*
 * Removes the object from the list that compares equally to obj.
 */
void natnl_list_delete(natnl_list_t *list, void *obj)
{
#ifdef USE_DISCONNECT_LOCK
	if (list->disconn_lock)
		pj_mutex_lock(list->disconn_lock);		// +Roger - avoided UDT to free socket at the same time
#endif
	natnl_list_delete_at(list, natnl_list_get_index(list, obj));

#ifdef USE_DISCONNECT_LOCK
	if (list->disconn_lock)
		pj_mutex_unlock(list->disconn_lock);
#endif
}

/*
 * Removes and frees an object from the list at the specified index
 */
void natnl_list_delete_at(natnl_list_t *list, int i)
{
	//void *tmp = list->obj_arr[i];
    if(i >= list->num_objs || i < 0) {
        return;
    }

	list->obj_free(&list->obj_arr[i]);
#if 1 // using memmove to solve performance issue.
	pj_array_erase(list->obj_arr, sizeof(void*), list->num_objs, i);
#else
    /* Shift the rest of the object pointers one to the left */
    for(; i < list->num_objs - 1; i++)
        list->obj_arr[i] = list->obj_arr[i+1];
#endif

    list->obj_arr[list->num_objs-1] = NULL;
    list->num_objs--;
}

/*
 * Frees each element in the list and then the list and then the list struct
 * itself.
 */
void natnl_list_free(natnl_list_t **list)
{
    if (!*list)
        return;

    int i;

    for(i = 0; i < (*list)->num_objs; i++) {
        if ((*list)->obj_arr[i]) {
            (*list)->obj_free(&(*list)->obj_arr[i]);
            (*list)->obj_arr[i] = NULL;
        }
    }

	if ((*list)->obj_arr) {
		free((*list)->obj_arr);
		(*list)->obj_arr = NULL;
	}

#ifdef USE_DISCONNECT_LOCK
	// +Roger - Destroy disconnect mutex
	if((*list)->disconn_lock) {
		pj_mutex_destroy((*list)->disconn_lock);
		(*list)->disconn_lock = NULL;
	}
#endif

    free(*list);
    *list = NULL;
}

