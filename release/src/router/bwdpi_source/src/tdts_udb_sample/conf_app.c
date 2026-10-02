/*
 * Copyright 2014 Trend Micro Incorporated
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software without 
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "conf_app.h"

/*
 * parse bwdpi.app.db and store the info
 * in a list headed from @head
 */
int init_app_inf(struct list_head *head)
{
	FILE *pf;
	static char line_buf[256];
	static char app_name[256];
	int cat_id, app_id, beh_id;

	pf = fopen(APP_INF_DB_PATH, "r");

	if (!pf)
	{
		DBG("get %s error \n", APP_INF_DB_PATH);
		return -1;
	}

	while (fgets(line_buf, sizeof(line_buf), pf))
	{
		app_inf_t* app_inf;

		if ('#' == line_buf[0])
		{
			continue;
		}

		sscanf(line_buf, "%d,%d,%d,%[^\n]", &cat_id, &app_id, &beh_id, app_name);
		app_inf = (app_inf_t *) malloc(sizeof(app_inf_t));
		if (app_inf)
		{
			app_inf->cat_id = cat_id;
			app_inf->app_id = app_id;
			app_inf->beh_id = beh_id;
			app_inf->app_name = strdup(app_name);

			list_add_tail(&app_inf->list, head);
		}
	}
	fclose(pf);

	return 0;
}

void free_app_inf(struct list_head *head)
{
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, head)
	{
		app_inf_t *app_inf = list_entry(pos, app_inf_t, list);

		free(app_inf->app_name);
		list_del(&app_inf->list);
		free(app_inf);
	}
}

char* search_app_inf(struct list_head *head, unsigned cat_id, unsigned app_id)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, head)
	{
		app_inf_t *app_inf = list_entry(pos, app_inf_t, list);
		if (app_inf->cat_id == cat_id && app_inf->app_id == app_id)
		{
			return app_inf->app_name;
		}
	}

	return NULL;
}

/*
 * parse bwdpi.cat.db and store the info
 * in a list headed from @head
 */
int init_app_cat(struct list_head *head)
{
	FILE *pf;
	static char line_buf[256];
	static char cat_name[256];
	unsigned cat_id;

	pf = fopen(APP_CAT_DB_PATH, "r");

	if (!pf)
	{
		DBG("get %s error \n", APP_CAT_DB_PATH);
		return -1;
	}

	while (fgets(line_buf, sizeof(line_buf), pf))
	{
		app_cat_t* cat;

		if ('#' == line_buf[0])
		{
			continue;
		}

		sscanf(line_buf, "%u,%[^\n]", &cat_id, cat_name);

		cat = (app_cat_t *) malloc(sizeof(app_cat_t));
		if (cat)
		{
			cat->cat_id = cat_id;
			cat->cat_name = strdup(cat_name);

			list_add_tail(&cat->list, head);
		}
	}
	fclose(pf);

	return 0;
}

void free_app_cat(struct list_head *head)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, head)
	{
		app_cat_t *app_cat = list_entry(pos, app_cat_t, list);

		free(app_cat->cat_name);
		list_del(&app_cat->list);
		free(app_cat);
	}
}

char* search_app_cat(struct list_head *head, unsigned cat_id)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, head)
	{
		app_cat_t *cat = list_entry(pos, app_cat_t, list);

		if (cat->cat_id == cat_id)
		{
			return cat->cat_name;
		}
	}
	return NULL;
}

/*
 * parse bwdpi.devdb.db and store the info
 * in a list headed from @head
 */
int init_dev_os(struct list_head *head)
{
	FILE *pf;
	static char line_buf[400];
	static char vendor_name[100], os_name[100]
		, class_name[100], type_name[100], dev_name[100]
		, family_name[100];
	unsigned vendor_id, os_id, class_id, type_id, dev_id, family_id;

	pf = fopen(DEV_OS_DB_PATH, "r");

	if (!pf)
	{
		DBG("get %s error \n", DEV_OS_DB_PATH);
		return -1;
	}

	while (fgets(line_buf, sizeof(line_buf), pf))
	{
		dev_os_t* dev_os;

		if ('#' == line_buf[0])
		{
			continue;
		}

		//replace \n to \0
		if ('\n' == line_buf[strlen(line_buf) - 1])
		{
			line_buf[strlen(line_buf) - 1] = '\0';
		}

#ifndef DEVDB_PATT
#define DEVDB_PATT "%u,%u,%u,%u,%u,%u,\"%[^\"]\",\"%[^\"]\",\"%[^\"]\",\"%[^\"]\",\"%[^\"]\",\"%[^\"]\""
#endif
		sscanf(line_buf, DEVDB_PATT
			, &vendor_id, &os_id, &class_id, &type_id, &dev_id
			, &family_id
			, vendor_name, os_name, class_name, type_name, dev_name
			, family_name);

		dev_os = (dev_os_t *) malloc(sizeof(dev_os_t));
		if (dev_os)
		{
			dev_os->vendor_id = vendor_id;
			dev_os->os_id = os_id;
			dev_os->class_id = class_id;
			dev_os->type_id = type_id;
			dev_os->dev_id = dev_id;
			dev_os->family_id = family_id;
			dev_os->vendor_name = strdup(vendor_name);
			dev_os->os_name = strdup(os_name);
			dev_os->class_name = strdup(class_name);
			dev_os->type_name = strdup(type_name);
			dev_os->dev_name = strdup(dev_name);
			dev_os->family_name = strdup(family_name);

			list_add_tail(&dev_os->list, head);
		}
	}
	fclose(pf);

	return 0;
}

void free_dev_os(struct list_head *head)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, head)
	{
		dev_os_t *dev_os = list_entry(pos, dev_os_t, list);

		free(dev_os->vendor_name);
		free(dev_os->os_name);
		free(dev_os->class_name);
		free(dev_os->type_name);
		free(dev_os->dev_name);
		free(dev_os->family_name);
		list_del(&dev_os->list);
		free(dev_os);
	}
}

dev_os_t* search_dev_os(struct list_head *head
	, unsigned vendor_id, unsigned os_id, unsigned class_id, unsigned type_id, unsigned dev_id
	, unsigned family_id)
{
	struct list_head *pos, *next;

	dev_os_t *dev_os_optimize1 = NULL;

	list_for_each_safe(pos, next, head)
	{
		dev_os_t *dev_os = list_entry(pos, dev_os_t, list);
		if ((dev_os->vendor_id == vendor_id) &&
			(dev_os->os_id == os_id || 0 == os_id) &&
			(dev_os->class_id == class_id || 0 == class_id) &&
			(dev_os->type_id == type_id || 0 == type_id) &&
			(dev_os->dev_id == dev_id || 0 == dev_id) &&
			(dev_os->family_id == family_id || 0 == family_id))
		{
			return dev_os;
		}

		//user interesting dev_name, such as iphone
		if ((dev_os->vendor_id == vendor_id) &&
			//(dev_os->dev_id == dev_id || 0 == dev_id ) )
			(dev_os->os_id == os_id || 0 == os_id))
		{
			dev_os_optimize1 = dev_os;
		}
	}

	if (dev_os_optimize1)
	{
		return dev_os_optimize1;
	}

	return NULL;
}

void _trim(char *s, char delim)
{
	char *p = s, *e;

	/* skip heading delim */
	while (delim == *p)
		p++;

	if (*p)
	{ /* skip tailing delim */
		e = p + strlen(p) - 1;
		while ((e != s) && (delim == *e))
			e--;
		*++e = 0;

		memmove(s, p, e - p + 1);
	}
	else
	{ /* empty */
		*s = 0;
	}
}

/*
 * parse bwdpi.rule.db and store the info
 * in a list headed from @head
 */
int init_rule_db(struct list_head *head)
{
	FILE *pf;
	static char line_buf[256];
	static char cat_name[256];
	unsigned cat_id;

	char *tmp = NULL;

	pf = fopen(RULE_DB_PATH, "r");

	if (!pf)
	{
		DBG("get %s error \n", RULE_DB_PATH);
		return -1;
	}

	while (fgets(line_buf, sizeof(line_buf), pf))
	{
		/* We lend cat struct to store rule info */
		app_cat_t* cat;

		if ('#' == line_buf[0])
		{
			continue;
		}

		//trim special characters
		tmp = strchr(line_buf, '#');
		if (tmp)
		{
			*tmp = 0x00;
		}
		_trim(line_buf, '\t');
		_trim(line_buf, ' ');

		sscanf(line_buf, "%u,%[^\n]", &cat_id, cat_name);

		cat = (app_cat_t *) malloc(sizeof(app_cat_t));
		if (cat)
		{
			cat->cat_id = cat_id;
			cat->cat_name = strdup(cat_name);

			list_add_tail(&cat->list, head);
		}
	}
	fclose(pf);

	return 0;
}

void free_rule_db(struct list_head *head)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, head)
	{
		app_cat_t *app_cat = list_entry(pos, app_cat_t, list);

		free(app_cat->cat_name);
		list_del(&app_cat->list);
		free(app_cat);
	}
}

char* search_rule_db(struct list_head *head, unsigned cat_id)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, head)
	{
		app_cat_t *cat = list_entry(pos, app_cat_t, list);

		if (cat->cat_id == cat_id)
		{
			return cat->cat_name;
		}
	}
	return NULL;
}
