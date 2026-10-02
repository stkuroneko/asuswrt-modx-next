#include "PMS_DBAPIs.h"

static int action_table=99;
char *data=NULL;
char *req_act=NULL;
char *srcName=NULL;

static void test_getall_user(void){
	int ret=0;
	int acc_num, group_num;
	PMS_ACCOUNT_INFO_T *account_list, *follow_account;
	PMS_ACCOUNT_GROUP_INFO_T *group_list;

	// get the account list
	if(( ret = PMS_GetAccountInfo(PMS_ACTION_GET_FULL, &account_list, &group_list, &acc_num, &group_num)) < 0){
		printf("Can't read the account list.\n");
		return;
	}

	for(follow_account = account_list; follow_account != NULL; follow_account = follow_account->next){
		printf("%d\t   %s\t   %s\t  %s\t   %s\n", follow_account->active, follow_account->name, follow_account->passwd, follow_account->desc,  follow_account->email);
		
		PMS_OWNED_INFO_T *owned_group=follow_account->owned_group;
		while(owned_group!=NULL){
			PMS_ACCOUNT_GROUP_INFO_T *Group_owned=(PMS_ACCOUNT_GROUP_INFO_T *)owned_group->member;
			printf("Owned Group: %s\t", Group_owned->name);
			owned_group=owned_group->next;
		}
		printf("\n");
	}
	
	PMS_FreeAccInfo(&account_list, &group_list);
	return;
}

static void test_getall_userGroup(void){
	int ret=0;
	int acc_num, group_num;
	PMS_ACCOUNT_INFO_T *account_list;
	PMS_ACCOUNT_GROUP_INFO_T *group_list, *follow_group;

	// get the account list
	if(( ret = PMS_GetAccountInfo(PMS_ACTION_GET_FULL, &account_list, &group_list, &acc_num, &group_num)) < 0){
		printf("Can't read the account list.\n");
		return;
	}

	for(follow_group = group_list; follow_group != NULL; follow_group = follow_group->next){
		printf("%d\t   %s\t   %s\n", follow_group->active, follow_group->name, follow_group->desc);
		
		PMS_OWNED_INFO_T *owned_account=follow_group->owned_account;
		while(owned_account!=NULL){
			PMS_ACCOUNT_INFO_T *Account_owned=(PMS_ACCOUNT_INFO_T *)owned_account->member;
			printf("Owned Account: %s\t", Account_owned->name);
			owned_account=owned_account->next;
		}
		printf("\n");
	}

	PMS_FreeAccInfo(&account_list, &group_list);
	return;
}


static void test_getall_dev(void)
{
	int ret=0;
	int dev_num, group_num;
	PMS_DEVICE_INFO_T *device_list, *follow_account;
	PMS_DEVICE_GROUP_INFO_T *group_list;

	// get the account list
	if(( ret = PMS_GetDeviceInfo(PMS_ACTION_GET_FULL, &device_list, &group_list, &dev_num, &group_num)) < 0){
		printf("Can't read the account list.\n");
		return;
	}

	for(follow_account = device_list; follow_account != NULL; follow_account = follow_account->next){
		printf("%d\t   %s\t   %s\t %s\t %d\n", follow_account->active, follow_account->mac, follow_account->desc, follow_account->devname,
			follow_account->devtype);
		
		PMS_OWNED_INFO_T *owned_group=follow_account->owned_group;
		while(owned_group!=NULL){
			PMS_DEVICE_GROUP_INFO_T *Group_owned=(PMS_DEVICE_GROUP_INFO_T *)owned_group->member;
			printf("Owned Group: %s\t", Group_owned->name);
			owned_group=owned_group->next;
		}
		printf("\n");
	}
	
	PMS_FreeDevInfo(&device_list, &group_list);
	return;


}

static void test_getall_devGroup(void)
{
	int ret=0;
	int dev_num, group_num;
	PMS_DEVICE_INFO_T *device_list;
	PMS_DEVICE_GROUP_INFO_T *group_list, *follow_group;

	// get the account list
	if(( ret = PMS_GetDeviceInfo(PMS_ACTION_GET_FULL, &device_list, &group_list, &dev_num, &group_num)) < 0){
		printf("Can't read the account list.\n");
		return;
	}

	for(follow_group = group_list; follow_group != NULL; follow_group = follow_group->next){
		printf("%d\t   %s\t   %s\n", follow_group->active, follow_group->name, follow_group->desc);
		
		PMS_OWNED_INFO_T *owned_device=follow_group->owned_device;
		while(owned_device!=NULL){
			PMS_DEVICE_INFO_T *Device_owned=(PMS_DEVICE_INFO_T *)owned_device->member;
			printf("Owned Device: %s\t", Device_owned->mac);
			owned_device=owned_device->next;
		}
		printf("\n");
	}

	PMS_FreeDevInfo(&device_list, &group_list);
	return;


}


static void test_getall(void)
{
	
	switch(action_table){
		case TABLE_ACC_USER:
			test_getall_user();			
			break;
		case TABLE_DEV_ACCOUNT:
			test_getall_dev();			
			break;
		case TABLE_ACC_GROUP:
			test_getall_userGroup();			
			break;
		case TABLE_DEV_GROUP:
			test_getall_devGroup();			
			break;
		default:
			break;
	}
	return;
}
static void test_update(char *add_data)
{
	char *delm=">";
	char *ptrArray[16]={0};
	int num=0, i;
	char *tmp=NULL;
	char *ori_str=NULL;
	
	ori_str=strdup(add_data);
	while((tmp=strsep(&add_data, delm)) != NULL ){
		if(*tmp !='\0')	ptrArray[num]=strdup(tmp);
		else ptrArray[num]=NULL;
		num++;
	}


	switch(action_table){
		case TABLE_ACC_USER:
		{
			PMS_ACCOUNT_INFO_T *tmp_node=NULL;
		
			if((tmp_node=PMS_list_Account_new(5, ptrArray[0], 
							     ptrArray[1],
							     ptrArray[2],
						  	     ptrArray[3],
						   	     ptrArray[4])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionAccountInfo(PMS_ACTION_UPDATE, (void *)tmp_node, 0);
			} 
			PMS_list_ACCOUNT_free(tmp_node);
		}
			break;
		case TABLE_ACC_GROUP:
		{
			PMS_ACCOUNT_GROUP_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_AccountGroup_new(3, ptrArray[0],
								  ptrArray[1],
								  ptrArray[2])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionAccountInfo(PMS_ACTION_UPDATE, (void *)tmp_node, 1);
			} 
			PMS_list_ACCOUNT_GROUP_free(tmp_node);
		}
			break;
		case TABLE_DEV_ACCOUNT:
		{
			PMS_DEVICE_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_Device_new(5, ptrArray[0],
							    ptrArray[1],
							    ptrArray[2],
							    ptrArray[3],
							    ptrArray[4])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionDeviceInfo(PMS_ACTION_UPDATE, (void *)tmp_node, 0);
			} 
			PMS_list_DEVICE_free(tmp_node);
		}

			break;
		case TABLE_DEV_GROUP:
		{
			PMS_DEVICE_GROUP_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_DeviceGroup_new(3, ptrArray[0],
								  ptrArray[1],
								  ptrArray[2])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionDeviceInfo(PMS_ACTION_UPDATE, (void *)tmp_node, 1);
			} 
			PMS_list_DEVICE_GROUP_free(tmp_node);
		}

			break;
		case TABLE_USER2GROUP:
				PMS_ActAccMatchInfo(PMS_ACTION_UPDATE, num-1, ori_str);
			break;
		case TABLE_GROUP2USER:
				PMS_ActAccGroupMatchInfo(PMS_ACTION_UPDATE, num-1, ori_str);
			break;
		case TABLE_DEV2GROUP:
				PMS_ActDevMatchInfo(PMS_ACTION_UPDATE, num-1,  ori_str);
			break;
		case TABLE_GROUP2DEV:
				PMS_ActDevGroupMatchInfo(PMS_ACTION_UPDATE, num-1, ori_str);
			break;

		default:
			break;

	}
	for(i=0; i<num; i++){
		free(ptrArray[i]);
	}
	free(ori_str);
}

static void test_modify(char *add_data)
{
	char *delm=">";
	char *ptrArray[16]={0};
	int num=0, i;
	char *tmp=NULL;
	char *ori_str=NULL;
	
	ori_str=strdup(add_data);
	while((tmp=strsep(&add_data, delm)) != NULL ){
		if(*tmp !='\0')	ptrArray[num]=strdup(tmp);
		else ptrArray[num]=NULL;
		num++;	
	}
	switch(action_table){
		case TABLE_ACC_USER:
		{
			PMS_ACCOUNT_INFO_T *tmp_node=NULL;
		
			if((tmp_node=PMS_list_Account_new(5, ptrArray[0], 
							     ptrArray[1],
							     ptrArray[2],
						  	     ptrArray[3],
						   	     ptrArray[4])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionAccountInfo(PMS_ACTION_MODIFY, (void *)tmp_node, 0, srcName);
			} 
			PMS_list_ACCOUNT_free(tmp_node);
		}
			break;
		case TABLE_ACC_GROUP:
		{
			PMS_ACCOUNT_GROUP_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_AccountGroup_new(3, ptrArray[0],
								  ptrArray[1],
								  ptrArray[2])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionAccountInfo(PMS_ACTION_MODIFY, (void *)tmp_node, 1, srcName);
			} 
			PMS_list_ACCOUNT_GROUP_free(tmp_node);
		}
			break;
		case TABLE_DEV_ACCOUNT:
		{
			PMS_DEVICE_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_Device_new(5, ptrArray[0],
							    ptrArray[1],
							    ptrArray[2],
							    ptrArray[3],
							    ptrArray[4])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionDeviceInfo(PMS_ACTION_MODIFY, (void *)tmp_node, 0, srcName);
			} 
			PMS_list_DEVICE_free(tmp_node);
		}

			break;
		case TABLE_DEV_GROUP:
		{
			PMS_DEVICE_GROUP_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_DeviceGroup_new(3, ptrArray[0],
								  ptrArray[1],
								  ptrArray[2])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionDeviceInfo(PMS_ACTION_MODIFY, (void *)tmp_node, 1, srcName);
			} 
			PMS_list_DEVICE_GROUP_free(tmp_node);
		}

			break;
#if 0
		case TABLE_USER2GROUP:
				PMS_ActAccMatchInfo(PMS_ACTION_UPDATE, num-1, ori_str);
			break;
		case TABLE_GROUP2USER:
				PMS_ActAccGroupMatchInfo(PMS_ACTION_UPDATE, num-1, ori_str);
			break;
		case TABLE_DEV2GROUP:
				PMS_ActDevMatchInfo(PMS_ACTION_UPDATE, num-1,  ori_str);
			break;
		case TABLE_GROUP2DEV:
				PMS_ActDevGroupMatchInfo(PMS_ACTION_UPDATE, num-1, ori_str);
			break;
#endif
		default:
			break;

	}
	for(i=0; i<num; i++){
		free(ptrArray[i]);
	}
	free(ori_str);
}

static void test_delete(char *add_data)
{
	char *delm=">";
	char *ptrArray[16]={0};
	int num=0;
	char *tmp=NULL;
	int i=0;

	while((tmp=strsep(&add_data, delm)) != NULL ){
		if(*tmp !='\0')	ptrArray[num]=strdup(tmp);
		else ptrArray[num]=NULL;
		num++;
	}


	switch(action_table){
		case TABLE_ACC_USER:
		{
			PMS_ACCOUNT_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_Account_new(2, ptrArray[0],
							     ptrArray[1])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				//tmp_node->name=ptrArray[0];
				PMS_ActionAccountInfo(PMS_ACTION_DELETE, (void *)tmp_node, 0);
			} 
			PMS_list_ACCOUNT_free(tmp_node);
		}
			break;
		case TABLE_ACC_GROUP:
		{
			PMS_ACCOUNT_GROUP_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_AccountGroup_new(2, ptrArray[0],
								  ptrArray[1])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionAccountInfo(PMS_ACTION_DELETE, (void *)tmp_node, 1);
			} 
			PMS_list_ACCOUNT_GROUP_free(tmp_node);
		}
			break;
		case TABLE_DEV_ACCOUNT:
		{
			PMS_DEVICE_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_Device_new(2, ptrArray[0],
							     ptrArray[1])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				//tmp_node->name=ptrArray[0];
				PMS_ActionDeviceInfo(PMS_ACTION_DELETE, (void *)tmp_node, 0);
			} 
			PMS_list_DEVICE_free(tmp_node);

		}
			break;
		case TABLE_DEV_GROUP:
		{
			PMS_DEVICE_GROUP_INFO_T *tmp_node=NULL;
			if((tmp_node=PMS_list_DeviceGroup_new(2, ptrArray[0],
								  ptrArray[1])) == NULL){
				printf("memory allocate failed\n");
				return;
			}else{
				PMS_ActionDeviceInfo(PMS_ACTION_DELETE, (void *)tmp_node, 1);
			} 
			PMS_list_DEVICE_GROUP_free(tmp_node);
		}
			break;
		case TABLE_USER2GROUP:
			break;
		case TABLE_GROUP2USER:
			break;
		case TABLE_DEV2GROUP:
			break;
		case TABLE_GROUP2DEV:
			break;

		default:
			break;
	}

	for(i=0; i<num; i++){
		free(ptrArray[i]);
	}

}

static void usage()
{
	printf("-a\t request actions [update|modify|delete|getall]\n");
	printf("-s\t modify target name [xxxx]\n");
	printf("-d\t input data ex.\"0>John>ssss>sw>john@asus.com\"\n");
	printf("-t\t requested table [user|userGroup|dev|devGroup|user2group|group2user|dev2group|group2dev]\n");
}

static int CheckData(char *str)
{
	if(str == NULL)
		return 1;
	else if (strchr(str, '>') == NULL)
		return 1;
	else
		return 0;
}

void free_opt()
{
	if(data!=NULL) free(data);
	if(req_act!=NULL) free(req_act);
	if(srcName!=NULL) free(srcName);
}
int main(int argc, char **argv)
{
	int ch;
	int ret=0;

	if(argc<3){ 
		usage();
		return 1;
	}
	while((ch = getopt(argc,argv,"a:d:t:s:"))!= -1){
		switch(ch){
			case 'a':
				req_act=strdup(optarg);
				break;
			case 'd':
				data=strdup(optarg);
				if(CheckData(data)) {usage(); exit(1);}
				break;
			case 't':
				if (!strcmp(optarg, "user")){
					action_table=TABLE_ACC_USER;
				}else if (!strcmp(optarg, "userGroup")){
					action_table=TABLE_ACC_GROUP;
				}else if (!strcmp(optarg, "dev")){
					action_table=TABLE_DEV_ACCOUNT;
				}else if (!strcmp(optarg, "devGroup")){
					action_table=TABLE_DEV_GROUP;
				}else if (!strcmp(optarg, "user2group")){
					action_table=TABLE_USER2GROUP;
				}else if (!strcmp(optarg, "group2user")){
					action_table=TABLE_GROUP2USER;
				}else if (!strcmp(optarg, "dev2group")){
					action_table=TABLE_DEV2GROUP;
				}else if (!strcmp(optarg, "group2dev")){
					action_table=TABLE_GROUP2DEV;
				}else{
					printf("Unkown table!!\n");
					goto RET;
				}
				break;
			case 's':
				srcName=strdup(optarg);
				break;
			default:
				printf("Unknown option:%c\n",ch);
		}
	}
	if ((ret=PMS_CreateAllTables())!=0){ 
		printf("return value:%d\n", ret);
		exit(1);
	}	
	if (!strcmp(req_act, "update")){
		test_update(data);
	}else if (!strcmp(req_act, "delete")){
		test_delete(data);
	}else if (!strcmp(req_act, "modify")){
		test_modify(data);
	}else if (!strcmp(req_act, "getall")){
		test_getall();
	}else{
		printf("unknown action!!\n");
	}
RET:
	free_opt();
	return 0;
}
