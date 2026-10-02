/*
 * Copyright © 2021 ASUSTeK COMPUTER INC. All rights reserved.
 */

#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <json.h>

#include "shared.h"

#define JFFS_DEF_FILE "/rom/jffs.json"
#define RTCONFIG_FILE "/rom/rtconfig"
#define JFFS_AVAIL_LOW 0.05 // Available space < 5 %

typedef struct fsm_data {
	char name[32];
	int priority;
	off_t max_size;
	off_t min_size;
	off_t cur_size;
	char type[8];
	char path[64];
	struct fsm_data *next;
	struct fsm_data *priv;
} fsm_data_t;

typedef struct fsm_feature {
	char name[32];
	char rtconfig[32];
	struct fsm_data *data_first;
	struct fsm_data *data_last;
	int data_count;
	struct fsm_feature *next;
	struct fsm_feature *priv;
} fsm_feature_t;

fsm_feature_t *feature_first = NULL;
fsm_feature_t *feature_last = NULL;
int feature_count = 0;

static int _is_rtconfig_defined(const char* req)
{
	FILE *fp;
	int ret = 0;
	char buf[128] = {0};
	char *p = NULL;

	fp = fopen(RTCONFIG_FILE, "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			p = strchr(buf, '=');
			if (p)
				*p = '\0';
			if (!strcmp(req, buf)) {
				ret = 1;
				break;
			}
		}
		fclose(fp);
	}

	return ret;
}

void initial_jffs_quota()
{
	json_object *root_obj = NULL;
	json_object *jffs_obj = NULL, *jffs_array_obj = NULL;
	int jffs_array_len = 0, jffs_idx = 0;
	json_object *productid_obj = NULL;
	json_object *features_obj = NULL, *features_array_obj = NULL;
	int features_array_len = 0, features_idx = 0;
	json_object *feature_name_obj = NULL, *rtconfig_obj = NULL;
	json_object *data_obj = NULL, *data_array_obj = NULL;
	int data_array_len = 0, data_idx = 0;
	json_object *data_name_obj = NULL, *priority_obj = NULL;
	json_object *max_size_obj = NULL, *min_size_obj = NULL;
	json_object *type_obj = NULL, *path_obj = NULL;
	char productid[32] = {0};
	char rtconfig[32] = {0};
	fsm_feature_t *new_feature = NULL, *cur_feature = NULL;
	fsm_data_t *new_data = NULL;
	int exist = 0;

	nvram_safe_get_r("productid", productid, sizeof(productid));

	root_obj = json_object_from_file(JFFS_DEF_FILE);
	if (root_obj) {
		if (json_object_object_get_ex(root_obj, "jffs", &jffs_obj)) {
			/// productid
			jffs_array_len = json_object_array_length(jffs_obj);
			for (jffs_idx = 0; jffs_idx < jffs_array_len; jffs_idx++) {
				jffs_array_obj = json_object_array_get_idx(jffs_obj, jffs_idx);
				json_object_object_get_ex(jffs_array_obj, "productid", &productid_obj);
				json_object_object_get_ex(jffs_array_obj, "features", &features_obj);
				if (!productid_obj || !features_obj)
					continue;

				if (strcmp(productid, json_object_get_string(productid_obj))
				 && strcmp("general", json_object_get_string(productid_obj)))
					continue;

				/// features
				features_array_len = json_object_array_length(features_obj);
				for (features_idx = 0; features_idx < features_array_len; features_idx++) {
					features_array_obj = json_object_array_get_idx(features_obj, features_idx);
					json_object_object_get_ex(features_array_obj, "name", &feature_name_obj);
					json_object_object_get_ex(features_array_obj, "rtconfig", &rtconfig_obj);
					json_object_object_get_ex(features_array_obj, "data", &data_obj);
					if (!feature_name_obj || !rtconfig_obj || !data_obj)
						continue;

					// if rtconfig existed, skip
					cur_feature = feature_first;
					strlcpy(rtconfig, json_object_get_string(rtconfig_obj), sizeof(rtconfig));
					exist = 0;
					while (cur_feature) {
						if (!strcmp(cur_feature->rtconfig, rtconfig)) {
							exist = 1;
							break;
						}
						else
							cur_feature = cur_feature->next;
					}
					if (exist)
						continue;

					// rtconfig not support, skip
					if (!strncmp(rtconfig, "RTCONFIG",8) && !_is_rtconfig_defined(rtconfig))
						continue;

					// create new feature
					new_feature = calloc(sizeof(fsm_feature_t), 1);
					if (new_feature) {
						strlcpy(new_feature->name, json_object_get_string(feature_name_obj), sizeof(new_feature->name));
						strlcpy(new_feature->rtconfig, json_object_get_string(rtconfig_obj), sizeof(new_feature->rtconfig));

						/// data
						data_array_len = json_object_array_length(data_obj);
						for (data_idx = 0; data_idx < data_array_len; data_idx++) {
							data_array_obj = json_object_array_get_idx(data_obj, data_idx);
							json_object_object_get_ex(data_array_obj, "name", &data_name_obj);
							json_object_object_get_ex(data_array_obj, "priority", &priority_obj);
							json_object_object_get_ex(data_array_obj, "max_size", &max_size_obj);
							json_object_object_get_ex(data_array_obj, "min_size", &min_size_obj);
							json_object_object_get_ex(data_array_obj, "type", &type_obj);
							json_object_object_get_ex(data_array_obj, "path", &path_obj);
							if (!data_name_obj || !priority_obj || !max_size_obj || !min_size_obj || !type_obj || !path_obj)
								continue;

							new_data = calloc(sizeof(fsm_data_t), 1);
							if (new_data) {
								strlcpy(new_data->name, json_object_get_string(data_name_obj), sizeof(new_data->name));
								new_data-> priority = json_object_get_int(priority_obj);
								new_data-> max_size = json_object_get_int(max_size_obj);
								new_data-> min_size = json_object_get_int(min_size_obj);
								strlcpy(new_data->type, json_object_get_string(type_obj), sizeof(new_data->type));
								strlcpy(new_data->path, json_object_get_string(path_obj), sizeof(new_data->path));
								// add to feature
								if (new_feature->data_last) {
									new_data->priv = new_feature->data_last;
									new_feature->data_last->next = new_data;
									new_feature->data_last = new_data;
									new_feature->data_count++;
								}
								else {
									new_feature->data_first = new_data;
									new_feature->data_last = new_data;
									new_feature->data_count = 1;
								}
							}
						}

						// add to feature list
						if (feature_last) {
							new_feature->priv = feature_last;
							feature_last->next = new_feature;
							feature_last = new_feature;
							feature_count++;
						}
						else {
							feature_first = new_feature;
							feature_last = new_feature;
							feature_count = 1;
						}
					}
				}
			}
		}
		json_object_put(root_obj);
	}
}

void destroy_jffs_quota()
{
	fsm_feature_t *cur_feature = feature_first;
	fsm_data_t *cur_data = NULL;

	while (cur_feature) {
		cur_data = cur_feature->data_first;
		while (cur_data) {
			cur_feature->data_first = cur_data->next;
			free(cur_data);
			cur_data = cur_feature->data_first;
		}
		feature_first = cur_feature->next;
		free(cur_feature);
		cur_feature = feature_first;
	}
}

static off_t _get_data_size(const char* path)
{
	struct stat st;
	off_t size = 0;
	DIR *dirp;
	struct dirent *direntp;
	char fullpath[256] = {0};

	if (lstat(path, &st) < 0)
		return 0;
	if ((st.st_mode & S_IFMT) == S_IFDIR) {
		if ((dirp = opendir(path)) != NULL) {
			while((direntp = readdir(dirp)) != NULL) {
				if(!strcmp(direntp->d_name, ".") || !strcmp(direntp->d_name, ".."))
					continue;
				else {
					snprintf(fullpath, sizeof(fullpath), "%s/%s", path, direntp->d_name);
					size += _get_data_size(fullpath);
				}
			}
			closedir(dirp);
		}
		else
			perror("opendir");
	}
	else {
		size = (st.st_blksize >> 3) * st.st_blocks;
	}

	return (size);
}

static void _del_data(const char* path)
{
	struct stat st;
	DIR *dirp;
	struct dirent *direntp;
	char fullpath[256] = {0};

	if (lstat(path, &st) < 0)
		return;
	if ((st.st_mode & S_IFMT) == S_IFDIR) {
		if ((dirp = opendir(path)) != NULL) {
			while((direntp = readdir(dirp)) != NULL) {
				if(!strcmp(direntp->d_name, ".") || !strcmp(direntp->d_name, ".."))
					continue;
				else {
					snprintf(fullpath, sizeof(fullpath), "%s/%s", path, direntp->d_name);
					_del_data(fullpath);
				}
			}
			closedir(dirp);
		}
		else
			perror("opendir");
	}
	else {
		logmessage_normal("FSMD", "delete %s\n", path);
		unlink(path);
	}
}

void delete_p3_data()
{
	fsm_feature_t *cur_feature = feature_first;
	fsm_data_t *cur_data = NULL;

	while (cur_feature) {
		cur_data = cur_feature->data_first;
		while (cur_data) {
			if (cur_data->priority == 3)
				_del_data(cur_data->path);
			cur_data = cur_data->next;
		}
		cur_feature = cur_feature->next;
	}
}

void update_jffs_usage()
{
	fsm_feature_t *cur_feature = feature_first;
	fsm_data_t *cur_data = NULL;

	while (cur_feature) {
		cur_data = cur_feature->data_first;
		while (cur_data) {
			cur_data->cur_size = _get_data_size(cur_data->path);
			cur_data = cur_data->next;
		}
		cur_feature = cur_feature->next;
	}
}

int is_jffs_not_enough()
{
	struct statvfs stf;

	if (!statvfs("/jffs", &stf)) {
		if (stf.f_bavail < stf.f_blocks * JFFS_AVAIL_LOW)
			return 1;
		else
			return 0;
	}
	return 0;
}

void dump_jffs_usage(const char* path)
{
	fsm_feature_t *cur_feature = feature_first;
	fsm_data_t *cur_data = NULL;
	FILE *fp;

	if ((fp = fopen(path, "w+")) != NULL) {
		while (cur_feature) {
			fprintf(fp, "%s\n", cur_feature->name);
			cur_data = cur_feature->data_first;
			while (cur_data) {
				fprintf(fp, "\t%s (%d): %ld/%ld (%ld%%)\n", cur_data->name
					, cur_data->priority
					, cur_data->cur_size, cur_data->max_size
					, cur_data->cur_size*100/cur_data->max_size
					);
				cur_data = cur_data->next;
			}
			cur_feature = cur_feature->next;
		}
		fclose(fp);
	}
}

void check_jffs_quota()
{
	update_jffs_usage();

	if (is_jffs_not_enough()) {
		delete_p3_data();
		update_jffs_usage();
	}
}
