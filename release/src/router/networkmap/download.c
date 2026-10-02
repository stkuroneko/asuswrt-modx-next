#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <shared.h>
#include <shutils.h>
#include <time.h>
#include <shared.h>
#include <json.h>

#include "shared_func.h"
#include "protect_name.h"


#include "sm.h"
#include "networkmap.h"
#include "download.h"


int cloud_db_process() {

	char ver[NMP_VER_LEN + 1] = {0}, checksum[NMP_SHA256_CHECKSUM_LEN + 1] = {0}, checksum2[NMP_SHA256_CHECKSUM_LEN + 1] = {0};
	int flag = 0;
	int check_sig = 1;
	// int check_sig = 0;
	int file_enc = 1;
	

	flag = download_cloud_version(check_sig, file_enc);

	// cloud db type : have new version
	if(flag == NMP_SUCCESS) {

		get_nmp_db_from_local_version_file(check_sig, file_enc, ver, sizeof(ver), checksum, sizeof(checksum));
		// get_nmp_db_from_local_version_file(0, 1, ver, sizeof(ver), checksum, sizeof(checksum));	printf("[%s] download_version, flag = %d \n", __FUNCTION__, flag);

		printf("[%s] download_version, flag = %d, success \n", __FUNCTION__, flag);

	} else {
		printf("[%s] download_version, flag = %d, failure \n", __FUNCTION__, flag);

	}

	// flag = download_cloud_version();
	// exit(0);
	// flag = download_version();

	// NMP_DEBUG("[%s] download_version, flag = %d \n", __FUNCTION__, flag);

	return 0;
}

/*******************************************************************
* NAME: _get_version_of_version_file
* DESCRIPTION: Get version file data
* INPUT:  None
* OUTPUT:  None
* RETURN:  NMP_SUCCESS or NMP_FAIL
* NOTE:
*******************************************************************/

static int _get_version_of_version_file(const char *ver_file, const int check_sig, const int file_enc, char *version, const size_t version_len)
{
	int ret = NMP_FAIL;
	json_object *file_obj = NULL, *ver_obj = NULL;
	char *buf = NULL;
	const char *tmp_str;

	if(!ver_file)
	{
		return ret;
	}

	//read the dl version file without encryption
	buf = read_file(ver_file, check_sig, file_enc);
	// buf = read_file(ver_file, 0, 0);

	// printf("[%s] qq read_file = %s , check_sig = %d, file_enc = %d\n buf = %s \n", __FUNCTION__, ver_file, check_sig, file_enc, buf);


	if(buf)
	{
		file_obj = json_tokener_parse(buf);
		// printf("[%s] file_obj = %s \n", __FUNCTION__, json_object_get_string(file_obj));

		if(file_obj)
		{
			if(json_object_object_get_ex(file_obj, "version", &ver_obj))
			{
				tmp_str = json_object_get_string(ver_obj);
				if(tmp_str)
				{
					strlcpy(version, tmp_str, version_len);
					ret = NMP_SUCCESS;
				}
			}
			SAFE_JSON_OBJ_PUT(file_obj);
		}
		SAFE_FREE(buf);
	}

	// printf("[%s] version = %s, ret = %d \n", __FUNCTION__, version, ret);


	return ret;
}



/*******************************************************************
* NAME: download_version
* DESCRIPTION: Download and verify the version file
* INPUT:  None
* OUTPUT:  None
* RETURN:  NMP_SUCCESS or NMP_FAIL
* NOTE:
*******************************************************************/
int download_cloud_version(const int check_sig, const int file_enc)
// int download_cloud_version()
{
	json_object *file_obj = NULL, *ver_obj = NULL;
	char cur_ver[NMP_VER_LEN + 1] = {0}, dl_ver[NMP_VER_LEN + 1] = {0};
	const char *tmp_str;
	int ret = NMP_FAIL, r;
	char enc_path[256] = {0}, tmp[256];

	//check nmp directory
	if(!check_if_dir_exist(local_nmp_dir[0]))
	{
		if(check_if_file_exist(local_nmp_dir[0]))
		{
			snprintf(tmp, sizeof(tmp), "rm -rf %s", local_nmp_dir[0]);
			system(tmp);
		}
		mkdir(local_nmp_dir[0], 0744);
		printf("[%s]mkdir local_nmp_dir = %s \n", __FUNCTION__, local_nmp_dir[0]);
	}

	// int check_sig = 0, file_enc = 0;

	//download version file
	if(download_file(version_name[0], cloud_ver_path[0]) == NMP_SUCCESS)
	{
		printf("[%s] download_file = %s \n", __FUNCTION__, version_name[0]);

		// if(_get_version_of_version_file(cloud_ver_path[0], 1, 0, dl_ver, sizeof(dl_ver)) == NMP_SUCCESS)
		if(_get_version_of_version_file(cloud_ver_path[0], check_sig, 0, dl_ver, sizeof(dl_ver)) == NMP_SUCCESS)
		{

			printf("[%s] cloud_ver_path = %s, dl_ver = %s, parse NMP_SUCCESS \n", __FUNCTION__, cloud_ver_path[0], dl_ver);

			// r = _get_version_of_version_file(local_ver_path[0], 1, 1, cur_ver, sizeof(cur_ver));
			r = _get_version_of_version_file(local_ver_path[0], check_sig, file_enc, cur_ver, sizeof(cur_ver));

			printf("[%s] local_ver_path = %s, dl_ver = %s, cur_ver = %s, r = %d \n", __FUNCTION__, cloud_ver_path[0], dl_ver, cur_ver, r);

			//compare version [local & cloud] or local file not exist
			if((r == NMP_SUCCESS && atoi(dl_ver) != atoi(cur_ver)) ||  r == NMP_FAIL)
			{
				if(!file_enc) {
					unlink(local_ver_path[0]);
					eval("cp", (char*) cloud_ver_path[0], (char*) local_ver_path[0]);
					ret =  NMP_SUCCESS;

				} else {
					//encrypt file
					snprintf(enc_path, sizeof(enc_path), "%s_enc", local_ver_path[0]);
					// if(encrypt_file(cloud_ver_path[0], enc_path, 1) == NMP_SUCCESS)
					// if(encrypt_file(cloud_ver_path[0], enc_path, 0) == NMP_SUCCESS)
					if(encrypt_file(cloud_ver_path[0], enc_path, check_sig) == NMP_SUCCESS)
					{
						//remove old version
						unlink(local_ver_path[0]);
						eval("mv", enc_path, (char*) local_ver_path[0]);
						ret =  NMP_SUCCESS;
					}
					// unlink(cloud_ver_path[0]);
				}
			}
			else if(r == NMP_SUCCESS && atoi(dl_ver) == atoi(cur_ver))
			{
				// same version 
				ret = NMP_FAIL;
				unlink(cloud_ver_path[0]);
				printf("[%s], same version >> dl_ver = [%s] == cur_ver = [%s]\n", __FUNCTION__, dl_ver, cur_ver);

			}
		}
	} else {
		ret = NMP_FAIL;
		printf("[%s], download_file error\n", __FUNCTION__);
	}
	return ret;
}


int get_nmp_db_from_local_version_file(const int check_sig, const int file_enc, char *version, 
	const size_t ver_len, char *checksum, const size_t checksum_len)
{
	char *buf;
	const char *ver_str = NULL, *checksum_str = NULL, *db_type_str = NULL;
	json_object *file_obj = NULL, *db_obj = NULL, *db_array_obj = NULL;
	json_object *db_type_obj = NULL, *ver_obj = NULL, *checksum_obj = NULL;
	int ret = 1, i;

	// printf("cloud_ver_path[0] : %s \n", cloud_ver_path[0]);
	printf("[%s] local_ver_path[0] : %s \n", __FUNCTION__, local_ver_path[0]);

	// buf = read_file(cloud_ver_path[0], check_sig, file_enc);
	buf = read_file(local_ver_path[0], check_sig, file_enc);

	if(buf)
	{
		file_obj = json_tokener_parse(buf);

		if(file_obj)
		{
			printf("file_obj : %s \n", json_object_get_string(file_obj));
			// if(json_object_object_get_ex(file_obj, "feature_list", &db_obj))
			if(json_object_object_get_ex(file_obj, "db_list", &db_obj))
			{
				printf("[%s] db_obj : %s \n", __FUNCTION__, json_object_get_string(db_obj));

				int db_number = json_object_array_length(db_obj);

				printf("[%s] db_number : %d \n", __FUNCTION__, db_number);

				for (i = 0; i < db_number; i++) {

			    // get the i-th object in db array
			    db_array_obj = json_object_array_get_idx(db_obj, i);

					json_object_object_get_ex(db_array_obj, "db", &db_type_obj);
			    json_object_object_get_ex(db_array_obj, "version", &ver_obj);
			    json_object_object_get_ex(db_array_obj, "checksum", &checksum_obj);

					db_type_str = json_object_get_string(db_type_obj);
					ver_str = json_object_get_string(ver_obj);
					checksum_str = json_object_get_string(checksum_obj);

					printf("[%s] i = %d, db_type_str : %s \n", __FUNCTION__, i, db_type_str);
					printf("[%s] i = %d, ver_str : %s \n", __FUNCTION__, i, ver_str);
					printf("[%s] i = %d, checksum_str : %s \n", __FUNCTION__, i, checksum_str);

					if(ver_str && checksum_str && db_type_str)
					{
						strlcpy(version, ver_str, ver_len);
						strlcpy(checksum, checksum_str, checksum_len);
						ret = 0;

						download_nmp_db(db_type_str, ver_str, checksum_str, check_sig);

					}
				}

			}
			SAFE_JSON_OBJ_PUT(file_obj);
		}
		SAFE_FREE(buf);
	}
	return ret;
}



int download_nmp_db(const char *cur_nmp_db_type, const char *cur_nmp_db_ver, const char *cur_nmp_db_checksum, const int check_sig)
{
	char *buf = NULL;
	const char *dl_nmp_db_type = NULL, *dl_nmp_db_ver = NULL, *dl_nmp_db_checksum = NULL;
	json_object *file_obj = NULL, *nmp_db_obj = NULL, *db_array_obj = NULL, *db_type_obj = NULL, *ver_obj = NULL, *checksum_obj = NULL;
	
	char file_checksum[NMP_SHA256_CHECKSUM_LEN + 1] = {0};
	char db_type_path[128] = {0};

	const char *ver_str = NULL, *checksum_str = NULL, *db_type_str = NULL;

	int ret = NMP_FAIL;

	printf("[%s] cloud_ver_path : %s  \n", __FUNCTION__, cloud_ver_path[0]);

	//buf = read_file(local_ver_path[0], 0, 1);
	// buf = read_file(cloud_ver_path[0], 0, 0);
	buf = read_file(cloud_ver_path[0], check_sig, 0);
	// check_sig, file_enc
	
	printf("[%s] buf : %s \n", __FUNCTION__, buf);

	int i;
	
	if(buf)
	{
		file_obj = json_tokener_parse(buf);

		if(file_obj)
		{

			// if(json_object_object_get_ex(file_obj, "feature_list", &db_obj))
			if(json_object_object_get_ex(file_obj, "db_list", &nmp_db_obj))
			{

				int db_number = json_object_array_length(nmp_db_obj);

				printf("db_number : %d \n", db_number);

				for (i = 0; i < db_number; i++) {

			    // get the i-th object in db array
			    db_array_obj = json_object_array_get_idx(nmp_db_obj, i);


					if(json_object_object_get_ex(db_array_obj, "db", &db_type_obj))
					{
						dl_nmp_db_type = json_object_get_string(db_type_obj);
					}

					if(json_object_object_get_ex(db_array_obj, "version", &ver_obj))
					{
						dl_nmp_db_ver = json_object_get_string(ver_obj);
					}
					if(json_object_object_get_ex(db_array_obj, "checksum", &checksum_obj))
					{
						dl_nmp_db_checksum = json_object_get_string(checksum_obj);
					}
					
					printf("[%s] dl_nmp_db_type : %s \n", __FUNCTION__, dl_nmp_db_type);
					printf("[%s] dl_nmp_db_ver : %s \n", __FUNCTION__, dl_nmp_db_ver);
					printf("[%s] dl_nmp_db_checksum : %s \n", __FUNCTION__, dl_nmp_db_checksum);


					if(strcmp(cur_nmp_db_type, dl_nmp_db_type) == 0) {

						printf("[%s] i = %d, cur_nmp_db_type : %s, dl_nmp_db_type : %s \n", __FUNCTION__, i, cur_nmp_db_type, dl_nmp_db_type);

						snprintf(db_type_path, sizeof(db_type_path), "%s/%s", local_nmp_dir, db_type_str);
						printf("[%s] db_type_path : %s \n", __FUNCTION__, db_type_path);

						if(dl_nmp_db_ver && dl_nmp_db_checksum)
						{
							// if(!cur_nmp_db_ver || (atoi(dl_nmp_db_ver) > atoi(cur_nmp_db_ver)))
							if( (access( db_type_path, F_OK ) == -1) || (atoi(dl_nmp_db_ver) > atoi(cur_nmp_db_ver)))
							{
							
								char cloud_db_path[256] = {0};
								snprintf(cloud_db_path, sizeof(cloud_db_path), "%s/cloud_%s", local_nmp_dir[0], cur_nmp_db_type);
						
								printf("[%s] cloud_db_path : %s  \n", __FUNCTION__, cloud_db_path);
								
								//download nmp db
								//if(download_file(lib_nmp_name[0], local_lib_nmp_bk_path[0]) == NMP_SUCCESS)
								if(download_file(cur_nmp_db_type, cloud_db_path) == NMP_SUCCESS)
								{
									//compare checksum
									if(get_file_sha256_checksum(cloud_db_path, file_checksum, sizeof(file_checksum), 0) == NMP_SUCCESS)
									{
										printf("[%s] dl_nmp_db_checksum = %s, file_checksum : %s  \n", __FUNCTION__, dl_nmp_db_checksum, file_checksum);
										
										if(!strcmp(file_checksum, dl_nmp_db_checksum))
										{
											
											merge_local_db_and_cloud_db(cur_nmp_db_type, cloud_db_path);
											// unlink(keep_local_db_path);
											// unlink(cloud_db_path);
											// eval("mv", cloud_db_path, keep_local_db_path);

											ret = NMP_SUCCESS;
										}
									}
									else
									{
										//Cannot get checksum. remove this file

										// unlink(cloud_db_path);
									}
								}
							}
						}

					} else {

						printf("[%s] i = %d, db type diff, cur_nmp_db_type : %s, dl_nmp_db_type : %s \n", __FUNCTION__, i, cur_nmp_db_type, dl_nmp_db_type);

					}


				}
			}
			SAFE_JSON_OBJ_PUT(file_obj);
		}
		SAFE_FREE(buf);
	}
	return ret;
}




int merge_json_file(const char *db_type, const char *keep_local_db_path, const char *cloud_db_path) {


	char merge_nmp_db_path[256] = {0};
	int ret = 0;

  struct json_object *create_nmp_db_array = NULL;


	snprintf(merge_nmp_db_path, sizeof(merge_nmp_db_path), "%s/merge_%s", local_nmp_dir[0], db_type);
	printf("[%s] merge_nmp_db_path : %s  \n", __FUNCTION__, merge_nmp_db_path);

  //new a array
  create_nmp_db_array = json_object_new_array();

  if (!create_nmp_db_array)
  {
    printf("[%s] Cannot create array object \n", __FUNCTION__);
    ret = -1;
  }

	printf("[%s][%i] create_nmp_db_array len 1 = %d \n", __FUNCTION__, __LINE__, strlen(json_object_get_string(create_nmp_db_array)));
	printf("[%s][%i] parse keep_local_db_path = %s \n", __FUNCTION__, __LINE__, keep_local_db_path);

  // default db type
	parse_nmp_db(keep_local_db_path, create_nmp_db_array);

	printf("[%s][%i] create_nmp_db_array len 2 = %d \n", __FUNCTION__, __LINE__, strlen(json_object_get_string(create_nmp_db_array)));
	printf("[%s][%i] parse cloud_db_path = %s \n", __FUNCTION__, __LINE__, cloud_db_path);

	// cloud db type
	parse_nmp_db(cloud_db_path, create_nmp_db_array);

	printf("[%s][%i] create_nmp_db_array len 3 = %d \n", __FUNCTION__, __LINE__, strlen(json_object_get_string(create_nmp_db_array)));


  json_object_to_file(merge_nmp_db_path, create_nmp_db_array);

  json_object_put(create_nmp_db_array);

  return 0;
}


int parse_nmp_db(const char *parse_db_path, struct json_object *create_nmp_db_array)
{

	struct json_object *db_array = NULL, *db_array_obj = NULL;
	struct json_object *db_array_keyword = NULL, *db_array_type = NULL, *db_array_os_type = NULL;
	struct json_object *create_nmp_db_array_obj = NULL;

	// process db type
  db_array = json_object_from_file(parse_db_path);

  int i, db_array_len = 0;

  if(db_array) {
    db_array_len = json_object_array_length(db_array);
  } else {
    printf("[%s] json_tokener_parse failure, filename = %s \n", __FUNCTION__, parse_db_path);
    return -1;
  }


  for (i = 0; i < db_array_len; i++) {

		char db_keyword[64] = {0};
		char db_type[16] = {0};
		char db_os_type[16] = {0};

		// get the i-th object in db_array
		db_array_obj = json_object_array_get_idx(db_array, i);

		if(json_object_object_get_ex(db_array_obj, "keyword", &db_array_keyword))
		{
			snprintf(db_keyword, sizeof(db_keyword), "%s", json_object_get_string(db_array_keyword));
		}

		if(json_object_object_get_ex(db_array_obj, "type", &db_array_type))
		{
			snprintf(db_type, sizeof(db_type), "%s", json_object_get_string(db_array_type));
		}

		if(json_object_object_get_ex(db_array_obj, "os_type", &db_array_os_type))
		{
			snprintf(db_os_type, sizeof(db_os_type), "%s", json_object_get_string(db_array_os_type));
		}

		// printf("[%s][%i] db_keyword = %s \n", __FUNCTION__, __LINE__,  db_keyword);
		// printf("[%s][%i] db_type = %s \n", __FUNCTION__, __LINE__, db_type);
		// printf("[%s][%i] db_os_type = %s \n", __FUNCTION__, __LINE__, db_os_type);


    create_nmp_db_array_obj = json_object_new_object();

    json_object_object_add(create_nmp_db_array_obj, "keyword", json_object_new_string(db_keyword));
    json_object_object_add(create_nmp_db_array_obj, "type", json_object_new_string(db_type));
    json_object_object_add(create_nmp_db_array_obj, "os_type", json_object_new_string(db_os_type));


    json_object_array_add(create_nmp_db_array, create_nmp_db_array_obj);
	}



	return NMP_SUCCESS;
}


int merge_local_db_and_cloud_db(const char * db_type, const char * cloud_db_path) {


	char keep_local_db_path[256] = {0};
	snprintf(keep_local_db_path, sizeof(keep_local_db_path), "%s/keep_%s", local_nmp_dir[0], db_type);

	printf("[%s] keep_local_db_path : %s  \n", __FUNCTION__, keep_local_db_path);
	printf("[%s] cloud_db_path : %s  \n", __FUNCTION__, cloud_db_path);

	keep_local_nmp_db(db_type, keep_local_db_path, cloud_db_path);

	merge_json_file(db_type, keep_local_db_path, cloud_db_path);

	unlink(keep_local_db_path);
	unlink(cloud_db_path);
	// eval("mv", cloud_db_path, keep_local_db_path);

	return 0;
}

int keep_local_nmp_db(const char * db_type, const char * keep_local_db_path,  const char * cloud_db_path)
{

  int i;
  int ret = 0;
  char db_type_path[64] = {0};

  struct json_object *db_array = NULL;

  struct json_object *db_array_obj = NULL;
  struct json_object *db_array_keyword = NULL, *db_array_type = NULL, *db_array_os_type = NULL;

  if(strstr(NMP_CONV_TYPE_FILE, db_type)) {
  	snprintf(db_type_path, sizeof(db_type_path), "%s", NMP_CONV_TYPE_FILE);
  } else if(strstr(NMP_VENDOR_TYPE_FILE, db_type)) {
  	snprintf(db_type_path, sizeof(db_type_path), "%s", NMP_VENDOR_TYPE_FILE);
  } else if(strstr(NMP_BWDPI_TYPE_FILE, db_type)) {
  	snprintf(db_type_path, sizeof(db_type_path), "%s", NMP_BWDPI_TYPE_FILE);
  }

	printf("[%s] db_type = %s, db_type_path : %s  \n", __FUNCTION__, db_type, db_type_path);

  db_array = json_object_from_file(db_type_path);

  int db_array_len = 0;

  if(db_array) {
    db_array_len = json_object_array_length(db_array);
  } else {
    printf("[%s] json_tokener_parse failure, filename = %s \n", __FUNCTION__, db_type_path);
    return -1;
  }

  struct json_object *create_nmp_db = NULL;
  struct json_object *create_nmp_db_obj = NULL;
  struct json_object *create_nmp_db_array = NULL;
  struct json_object *create_nmp_db_array_obj = NULL;
  struct json_object *create_cloud_db_obj = NULL;

  //new a array
  create_nmp_db_array = json_object_new_array();

  if (!create_nmp_db_array)
  {
    printf("[%s] Cannot create array object \n", __FUNCTION__);
    ret = -1;
  }


  for (i = 0; i < db_array_len; i++) {

    char db_keyword[64] = {0};
    char db_type[16] = {0};
    char db_os_type[16] = {0};

    // get the i-th object in db_array
    db_array_obj = json_object_array_get_idx(db_array, i);

		if(json_object_object_get_ex(db_array_obj, "keyword", &db_array_keyword))
		{
			snprintf(db_keyword, sizeof(db_keyword), "%s", json_object_get_string(db_array_keyword));
		}

		if(json_object_object_get_ex(db_array_obj, "type", &db_array_type))
		{
			snprintf(db_type, sizeof(db_type), "%s", json_object_get_string(db_array_type));
		}

		if(json_object_object_get_ex(db_array_obj, "os_type", &db_array_os_type))
		{
			snprintf(db_os_type, sizeof(db_os_type), "%s", json_object_get_string(db_array_os_type));
		}

		printf("[%s] before db_keyword = %s \n", __FUNCTION__, db_keyword);
		printf("[%s] before db_type = %s \n", __FUNCTION__, db_type);
		printf("[%s] before db_os_type = %s \n", __FUNCTION__, db_os_type);


    int status = nmp_db_cmp(cloud_db_path, db_keyword, db_type, db_os_type);

    // get cloud db data, remove local nmp db
    if(status == NMP_SUCCESS) {

    	printf("[%s] nmp_db_cmp  status success  = %d \n", __FUNCTION__, status);
      // snprintf(db_state, 64, "%s", json_object_get_string(db_array_state));
    } else {

    	printf("[%s] nmp_db_cmp  status failure  = %d \n", __FUNCTION__, status);

	    create_nmp_db_array_obj = json_object_new_object();

	    json_object_object_add(create_nmp_db_array_obj, "keyword", json_object_new_string(db_keyword));
	    json_object_object_add(create_nmp_db_array_obj, "type", json_object_new_string(db_type));
	    json_object_object_add(create_nmp_db_array_obj, "os_type", json_object_new_string(db_os_type));


	    json_object_array_add(create_nmp_db_array, create_nmp_db_array_obj);
    }

		printf("[%s] after db_keyword = %s \n", __FUNCTION__, db_keyword);
		printf("[%s] after db_type = %s \n", __FUNCTION__, db_type);
		printf("[%s] after db_os_type = %s \n", __FUNCTION__, db_os_type);

	}


  json_object_to_file(keep_local_db_path, create_nmp_db_array);

  json_object_put(create_nmp_db_array);
  json_object_put(db_array);

  return 0;
}


int nmp_db_cmp(const char* cloud_db_path, char* local_db_keyword, char* local_db_type, char* local_db_os_type) {

	int i;
	struct json_object *db_array = NULL, *db_array_obj = NULL;
	struct json_object *db_array_keyword = NULL, *db_array_type = NULL, *db_array_os_type = NULL;


	db_array = json_object_from_file(cloud_db_path);

	int db_array_len = 0;

	if(db_array) {
		db_array_len = json_object_array_length(db_array);
	} else {
		printf("[%s] json_tokener_parse failure, filename = %s \n", __FUNCTION__, cloud_db_path);
		return -1;
  	}

	for (i = 0; i < db_array_len; i++) {

		char db_keyword[64] = {0};
		char db_type[16] = {0};
		char db_os_type[16] = {0};

		// get the i-th object in db_array
		db_array_obj = json_object_array_get_idx(db_array, i);

		if(json_object_object_get_ex(db_array_obj, "keyword", &db_array_keyword))
		{
			snprintf(db_keyword, sizeof(db_keyword), "%s", json_object_get_string(db_array_keyword));
		}

		if(json_object_object_get_ex(db_array_obj, "type", &db_array_type))
		{
			snprintf(db_type, sizeof(db_type), "%s", json_object_get_string(db_array_type));
		}

		if(json_object_object_get_ex(db_array_obj, "os_type", &db_array_os_type))
		{
			snprintf(db_os_type, sizeof(db_os_type), "%s", json_object_get_string(db_array_os_type));
		}

		if(strcmp(db_keyword, local_db_keyword) == 0) {

			snprintf(local_db_keyword, sizeof(db_keyword), "%s", db_keyword);
			snprintf(local_db_type, sizeof(db_type), "%s", db_type);
			snprintf(local_db_os_type, sizeof(db_os_type), "%s", db_os_type);

			printf("[%s] get cloud db type = local db type = %s, local_db_keyword = %s \n", __FUNCTION__, local_db_type, local_db_keyword);

			json_object_put(db_array);

			return NMP_SUCCESS;
		}
	}

	json_object_put(db_array);

	return -1;
}
