
#include <PMS_DBAPIs.h>
#include "dirent.h"
#include "sys/stat.h"

int PMS_ActionAccountInfo(int, void *, int , ...);
int PMS_ActionDeviceInfo(int, void *, int , ...);

int PMS_GetAccountInfo(int , PMS_ACCOUNT_INFO_T **input, PMS_ACCOUNT_GROUP_INFO_T **, int *, int *);
int PMS_GetDeviceInfo(int, PMS_DEVICE_INFO_T **input, PMS_DEVICE_GROUP_INFO_T **, int *, int *);
int PMS_CreateAllTables();

void PMS_FreeAccInfo(PMS_ACCOUNT_INFO_T **, PMS_ACCOUNT_GROUP_INFO_T **);
void PMS_FreeDevInfo(PMS_DEVICE_INFO_T **, PMS_DEVICE_GROUP_INFO_T **);

int PMS_AccAdd(sqlite3 *, PMS_ACCOUNT_INFO_T *, char *);
int PMS_AccGroupAdd(sqlite3 *, PMS_ACCOUNT_GROUP_INFO_T *, char *);
int PMS_AccModify(sqlite3 *, PMS_ACCOUNT_INFO_T *, char *);
int PMS_AccGroupModify(sqlite3 *, PMS_ACCOUNT_GROUP_INFO_T *, char *);
int PMS_AccDelete(sqlite3 *, PMS_ACCOUNT_INFO_T *,char *);
int PMS_AccGroupDelete(sqlite3 *, PMS_ACCOUNT_GROUP_INFO_T *, char *);
int PMS_AccUpdate(sqlite3 *, PMS_ACCOUNT_INFO_T *, char *);
int PMS_AccGroupUpdate(sqlite3 *, PMS_ACCOUNT_GROUP_INFO_T *, char *);

int PMS_DevAdd(sqlite3 *, PMS_DEVICE_INFO_T *, char *);
int PMS_DevGroupAdd(sqlite3 *, PMS_DEVICE_GROUP_INFO_T *, char *);
int PMS_DevModify(sqlite3 *, PMS_DEVICE_INFO_T *, char *);
int PMS_DevGroupModify(sqlite3 *, PMS_DEVICE_GROUP_INFO_T *, char *);
int PMS_DevDelete(sqlite3 *, PMS_DEVICE_INFO_T *, char *);
int PMS_DevGroupDelete(sqlite3 *, PMS_DEVICE_GROUP_INFO_T *, char *);
int PMS_DevUpdate(sqlite3 *, PMS_DEVICE_INFO_T *,char *);
int PMS_DevGroupUpdate(sqlite3 *, PMS_DEVICE_GROUP_INFO_T *, char *);

_PMS_ActionAccAPIs AccAPIsTable[]={
	{PMS_ACTION_ADD, PMS_AccAdd, PMS_AccGroupAdd},
	{PMS_ACTION_DELETE, PMS_AccDelete, PMS_AccGroupDelete},
	{PMS_ACTION_UPDATE, PMS_AccUpdate, PMS_AccGroupUpdate},
	{PMS_ACTION_MODIFY, PMS_AccModify, PMS_AccGroupModify},
	{0, NULL, NULL}
};

_PMS_ActionDevAPIs DevAPIsTable[]={
	{PMS_ACTION_ADD, PMS_DevAdd, PMS_DevGroupAdd},
	{PMS_ACTION_DELETE, PMS_DevDelete, PMS_DevGroupDelete},
	{PMS_ACTION_UPDATE, PMS_DevUpdate, PMS_DevGroupUpdate},
	{PMS_ACTION_MODIFY, PMS_DevModify, PMS_DevGroupModify},
	{0, NULL, NULL}
};

u32 Int_NULLhandler(char *Str)
{
	if(Str == NULL || strstr(Str, "NULL")){
		return 99;
	}else{
		return atoi(Str);
	}

}

PMS_ACCOUNT_INFO_T *PMS_list_Account_new(int num, char *para1, ...)
{
	char *parameters[16]={0};
	va_list ap;
	char *str=NULL;

	PMS_ACCOUNT_INFO_T *input=(PMS_ACCOUNT_INFO_T *)malloc(sizeof(PMS_ACCOUNT_INFO_T));
	if(input == NULL){
		return NULL;
	}else{
		str = para1;
		va_start(ap, para1);
		int idx=0;               
		while(idx != (num-1)) {
			str = va_arg(ap, char *); 
			if (str!=NULL){ 
				parameters[idx]=strdup(str);
			}else{
				parameters[idx]=NULL;
			}
			idx++;
		} 
		va_end(ap);
		input->active=Int_NULLhandler(para1);
	//	input->active=(u32)atoi(para1);
		input->name=parameters[0];
		input->passwd=parameters[1];
		input->desc=parameters[2];
		input->email=parameters[3];
		input->owned_group=NULL;
		input->next=NULL;
		return input;
	}
}

PMS_DEVICE_INFO_T *PMS_list_Device_new(int num, char *para1, ...)
{
	char *parameters[16]={0};
	va_list ap;
	char *str=NULL;
	PMS_DEVICE_INFO_T *input=(PMS_DEVICE_INFO_T *)malloc(sizeof(PMS_DEVICE_INFO_T));

	if(input == NULL){
		return NULL;
	}else{
		str = para1;
		va_start(ap, para1);
		int idx=0;               
		while(idx != (num-1)) {
			str = va_arg(ap, char *); 
			if (str!=NULL){ 
				parameters[idx]=strdup(str);
			}else{
				parameters[idx]=NULL;
			}
			idx++;
		} 
		va_end(ap); 

		input->active=Int_NULLhandler(para1);
		input->mac=parameters[0];
		input->desc=parameters[1];
		input->devname=parameters[2];
		input->devtype=Int_NULLhandler(parameters[3]);
		input->owned_group=NULL;
		input->next=NULL;
		return input;
	}
}

PMS_ACCOUNT_GROUP_INFO_T *PMS_list_AccountGroup_new(int num, char *para1, ...)
{
	char *parameters[16]={0};
	va_list ap;
	char *str=NULL;
	PMS_ACCOUNT_GROUP_INFO_T *input=(PMS_ACCOUNT_GROUP_INFO_T *)malloc(sizeof(PMS_ACCOUNT_GROUP_INFO_T));

	if(input == NULL){
		return NULL;
	}else{
		str = para1;
		va_start(ap, para1);
		int idx=0;               
		while(idx != (num-1)) {
			str = va_arg(ap, char *); 
			if (str!=NULL){ 
				parameters[idx]=strdup(str);
			}else{
				parameters[idx]=NULL;
			}
			idx++;
		} 
		va_end(ap); 
		
		//input->active=(u32)atoi(para1);
		input->active=Int_NULLhandler(para1);
		input->name=parameters[0];
		input->desc=parameters[1];
		input->owned_account=NULL;
		input->next=NULL;
		return input;
	}
}

PMS_DEVICE_GROUP_INFO_T *PMS_list_DeviceGroup_new(int num, char *para1, ...)
{
	char *parameters[16]={0};
	va_list ap;
	char *str=NULL;
	PMS_DEVICE_GROUP_INFO_T *input=(PMS_DEVICE_GROUP_INFO_T *)malloc(sizeof(PMS_DEVICE_GROUP_INFO_T));
	if(input == NULL){
		return NULL;
	}else{
		str = para1;
		va_start(ap, para1);
		int idx=0;               
		while(idx != (num-1)) {
			str = va_arg(ap, char *); 
			if (str!=NULL){ 
				parameters[idx]=strdup(str);
			}else{
				parameters[idx]=NULL;
			}
			idx++;
		} 
		va_end(ap); 

		//input->active=(u32)atoi(para1);
		input->active=Int_NULLhandler(para1);
		input->name=parameters[0];
		input->desc=parameters[1];
		input->owned_device=NULL;
		input->next=NULL;
		return input;
	}
}

PMS_OWNED_INFO_T *PMS_list_owned_new()
{
	PMS_OWNED_INFO_T *input=(PMS_OWNED_INFO_T *)malloc(sizeof(PMS_OWNED_INFO_T));
	if(input == NULL){
		return NULL;
	}else{
		input->next=NULL;
		return input;
	}
}

void PMS_list_Account_add2last(PMS_ACCOUNT_INFO_T **head, PMS_ACCOUNT_INFO_T *node)
{
	PMS_ACCOUNT_INFO_T *tmp=(*head);

	if((*head) == NULL){
		*head=node;
	}else{
		while(tmp->next != NULL){
			tmp=tmp->next;
		}
		tmp->next=node;
	}
}

void PMS_list_Device_add2last(PMS_DEVICE_INFO_T **head, PMS_DEVICE_INFO_T *node)
{

	PMS_DEVICE_INFO_T *tmp=(*head);
 
	if((*head) == NULL){
		*head=node;
	}else{
		while(tmp->next != NULL){
			tmp=tmp->next;
		}
		tmp->next=node;
	}
}

void PMS_list_AccountGroup_add2last(PMS_ACCOUNT_GROUP_INFO_T **head, PMS_ACCOUNT_GROUP_INFO_T *node)
{
	PMS_ACCOUNT_GROUP_INFO_T *tmp=(*head);

	if((*head) == NULL){
		*head=node;
	}else{
		while(tmp->next != NULL){
			tmp=tmp->next;
		}
		tmp->next=node;
	}
}

void PMS_list_DeviceGroup_add2last(PMS_DEVICE_GROUP_INFO_T **head, PMS_DEVICE_GROUP_INFO_T *node)
{
	PMS_DEVICE_GROUP_INFO_T *tmp=(*head);

	if((*head) == NULL){
		*head=node;
	}else{
		while(tmp->next != NULL){
			tmp=tmp->next;
		}
		tmp->next=node;
	}
}

void PMS_list_Owned_add2last(PMS_OWNED_INFO_T **head, PMS_OWNED_INFO_T *node)
{
	PMS_OWNED_INFO_T *tmp=(*head);

	if((*head) == NULL){
		*head=node;
	}else{
		while(tmp->next != NULL){
			tmp=tmp->next;
		}
		tmp->next=node;
	}
}

void PMS_list_owned_free(PMS_OWNED_INFO_T *head)
{
	PMS_OWNED_INFO_T *tmpNode;
	while(head!=NULL){
		tmpNode=head;
		head=head->next;
		free(tmpNode);
	}
}

void PMS_list_ACCOUNT_free(PMS_ACCOUNT_INFO_T *head)
{
	PMS_ACCOUNT_INFO_T *tmpNode;
	while(head!=NULL){
		tmpNode=head;
		head=head->next;
		free(tmpNode->name);
		free(tmpNode->passwd);
		free(tmpNode->desc);
		free(tmpNode->email);
		if(tmpNode->owned_group!=NULL){
			PMS_list_owned_free(tmpNode->owned_group);
		}
		free(tmpNode);
	}
}

void PMS_list_DEVICE_free(PMS_DEVICE_INFO_T *head)
{
	PMS_DEVICE_INFO_T *tmpNode;
	while(head!=NULL){
		tmpNode=head;
		head=head->next;
		free(tmpNode->mac);
		free(tmpNode->desc);
		free(tmpNode->devname);
		if(tmpNode->owned_group!=NULL){
			PMS_list_owned_free(tmpNode->owned_group);
		}
		free(tmpNode);
	}
}

void PMS_list_ACCOUNT_GROUP_free(PMS_ACCOUNT_GROUP_INFO_T *head)
{
	PMS_ACCOUNT_GROUP_INFO_T *tmpNode;
	while(head!=NULL){
		tmpNode=head;
		head=head->next;
		free(tmpNode->name);
		free(tmpNode->desc);
		if(tmpNode->owned_account!=NULL){
			PMS_list_owned_free(tmpNode->owned_account);
		}
		free(tmpNode);
	}
}

void PMS_list_DEVICE_GROUP_free(PMS_DEVICE_GROUP_INFO_T *head)
{
	PMS_DEVICE_GROUP_INFO_T *tmpNode;
	while(head!=NULL){
		tmpNode=head;
		head=head->next;
		free(tmpNode->name);
		free(tmpNode->desc);
		if(tmpNode->owned_device!=NULL){
			PMS_list_owned_free(tmpNode->owned_device);
		}
		free(tmpNode);
	}
}

char *transFormat(char *str)
{
	char *tmp=NULL;
	if(str!=NULL){
		tmp=(char *)malloc(strlen(str)+3);
		memset(tmp, 0, sizeof(tmp));
		if(tmp!=NULL){
			sprintf(tmp, "'%s'", str);
		}else{
			perror("Error in memory allocate\n");
		}
	}else{
		tmp=(char *)malloc(sizeof(char)*5);
		sprintf(tmp, "%s","NULL");
	}
		
	return tmp;
}

char *transFormatInt(char *str)
{
	char *tmp=NULL;
	if(str!=NULL){
		tmp=(char *)malloc(strlen(str)+1);
		memset(tmp, 0, sizeof(tmp));
		if(tmp!=NULL){
			sprintf(tmp, "%s", str);
		}else{
			perror("Error in memory allocate\n");
		}
	}else{
		tmp=(char *)malloc(sizeof(char)*5);
		sprintf(tmp, "%s","NULL");
	}
		
	return tmp;
}

int PMS_AccModify(sqlite3 *db, PMS_ACCOUNT_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	char *srcName=NULL;
	PMS_ACCOUNT_INFO_T *Node=head;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		if(Node->active != 99){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((char *)(&Node->active));
		}else{
			parameters[0]=transFormatInt(NULL);
		}
		parameters[1]=transFormat(Node->name);
		parameters[2]=transFormat(Node->passwd);
		parameters[3]=transFormat(Node->desc);
		parameters[4]=transFormat(Node->email);
		srcName=transFormat(reserved);
		ret=sqlite_modify(db, TABLE_ACC_USER, parameters, srcName);
	}
	int i=0;
	for(i=0; i<ACCUSERCOL; i++){
		free(parameters[i]);
	}
	if(srcName!=NULL) free(srcName);
	return ret;
}

int PMS_DevModify(sqlite3 *db, PMS_DEVICE_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_DEVICE_INFO_T *Node=head;
	int ret=0;
	char *srcName=NULL;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((Node->active == 147)? NULL: (char *)(&Node->active));
		parameters[1]=transFormat(Node->mac);
		parameters[2]=transFormat(Node->desc);
		parameters[3]=transFormat(Node->devname);
		Node->devtype=Node->devtype+'0';
		parameters[4]=transFormatInt((Node->devtype == 147)? NULL: (char *)(&Node->devtype));
		srcName=transFormat(reserved);
		ret=sqlite_modify(db, TABLE_DEV_ACCOUNT, parameters, srcName);
	}
	int i=0;
	for(i=0; i<DEVUSERCOL; i++){
		free(parameters[i]);
	}
	if(srcName!=NULL) free(srcName);
	return ret;
}


int PMS_AccGroupModify(sqlite3 *db, PMS_ACCOUNT_GROUP_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_ACCOUNT_GROUP_INFO_T *Node;
	char *srcName=NULL;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((Node->active == 147)? NULL: (char *)(&Node->active));
		parameters[1]=transFormat(Node->name);
		parameters[2]=transFormat(Node->desc);
		srcName=transFormat(reserved);
		ret=sqlite_modify(db, TABLE_ACC_GROUP, parameters, srcName);
	}
	int i=0;
	for(i=0; i<ACCGROUPCOL; i++){
		free(parameters[i]);
	}
	if(srcName!=NULL) free(srcName);
	return ret;
}

int PMS_DevGroupModify(sqlite3 *db, PMS_DEVICE_GROUP_INFO_T *head, char *reserved )
{
	char *parameters[16]={NULL};
	PMS_DEVICE_GROUP_INFO_T *Node;
	char *srcName=NULL;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((Node->active == 147)? NULL: (char *)(&Node->active));
		parameters[1]=transFormat(Node->name);
		parameters[2]=transFormat(Node->desc);
		srcName=transFormat(reserved);
		ret=sqlite_modify(db, TABLE_DEV_GROUP, parameters, srcName);
	}
	int i=0;
	for(i=0; i<DEVGROUPCOL; i++){
		free(parameters[i]);
	}
	if(srcName!=NULL) free(srcName);
	return ret;
}

int PMS_AccAdd(sqlite3 *db, PMS_ACCOUNT_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_ACCOUNT_INFO_T *Node=head;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((char *)(&Node->active));
		parameters[1]=transFormat(Node->name);
		parameters[2]=transFormat(Node->passwd);
		parameters[3]=transFormat(Node->desc);
		parameters[4]=transFormat(Node->email);
		ret=sqlite_update(db, TABLE_ACC_USER, parameters);
	}
	int i=0;
	for(i=0; i<ACCUSERCOL; i++){
		free(parameters[i]);
	}
	return ret;
}

int PMS_DevAdd(sqlite3 *db, PMS_DEVICE_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_DEVICE_INFO_T *Node=head;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((char *)(&Node->active));
		parameters[1]=transFormat(Node->mac);
		parameters[2]=transFormat(Node->desc);
		parameters[3]=transFormat(Node->devname);
		Node->devtype=Node->devtype+'0';
		parameters[4]=transFormatInt((char *)(&Node->devtype));
		ret=sqlite_update(db, TABLE_DEV_ACCOUNT, parameters);
	}
	int i=0;
	for(i=0; i<DEVUSERCOL; i++){
		free(parameters[i]);
	}
	return ret;
}


int PMS_AccGroupAdd(sqlite3 *db, PMS_ACCOUNT_GROUP_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_ACCOUNT_GROUP_INFO_T *Node;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((char *)(&Node->active));
		parameters[1]=transFormat(Node->name);
		parameters[2]=transFormat(Node->desc);
		ret=sqlite_update(db, TABLE_ACC_GROUP, parameters);
	}
	int i=0;
	for(i=0; i<ACCGROUPCOL; i++){
		free(parameters[i]);
	}
	return ret;
}

int PMS_DevGroupAdd(sqlite3 *db, PMS_DEVICE_GROUP_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_DEVICE_GROUP_INFO_T *Node;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((char *)(&Node->active));
		parameters[1]=transFormat(Node->name);
		parameters[2]=transFormat(Node->desc);
		ret=sqlite_update(db, TABLE_ACC_GROUP, parameters);
	}
	int i=0;
	for(i=0; i<DEVGROUPCOL; i++){
		free(parameters[i]);
	}
	return ret;
}

int PMS_AccDelete(sqlite3 *db, PMS_ACCOUNT_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_ACCOUNT_INFO_T *Node;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		parameters[0]=transFormat(Node->name);
		ret=sqlite_delete(db, TABLE_ACC_USER, parameters[0]);
	}
	free(parameters[0]);
	return ret;
}

int PMS_DevDelete(sqlite3 *db, PMS_DEVICE_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_DEVICE_INFO_T *Node;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		parameters[0]=transFormat(Node->mac);
		ret=sqlite_delete(db, TABLE_DEV_ACCOUNT, parameters[0]);
	}
	free(parameters[0]);
	return ret;
}

int PMS_AccGroupDelete(sqlite3 *db, PMS_ACCOUNT_GROUP_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_ACCOUNT_GROUP_INFO_T *Node;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		parameters[0]=transFormat(Node->name);
		ret=sqlite_delete(db, TABLE_ACC_GROUP, parameters[0]);
	}
	free(parameters[0]);
	return ret;
}

int PMS_DevGroupDelete(sqlite3 *db, PMS_DEVICE_GROUP_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_DEVICE_GROUP_INFO_T *Node;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		parameters[0]=transFormat(Node->name);
		ret=sqlite_delete(db, TABLE_DEV_GROUP, parameters[0]);
	}
	free(parameters[0]);
	return ret;
}

int PMS_AccUpdate(sqlite3 *db, PMS_ACCOUNT_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_ACCOUNT_INFO_T *Node;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((char *)(&Node->active));
		parameters[1]=transFormat(Node->name);
		parameters[2]=transFormat(Node->passwd);
		parameters[3]=transFormat(Node->desc);
		parameters[4]=transFormat(Node->email);
		ret=sqlite_update(db, TABLE_ACC_USER, parameters);
	}
	int i=0;
	for(i=0; i<ACCUSERCOL; i++){
		free(parameters[i]);
	}
	return ret;
}

int PMS_DevUpdate(sqlite3 *db, PMS_DEVICE_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_DEVICE_INFO_T *Node;
	int ret=0;
	
	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((char *)(&Node->active));
		parameters[1]=transFormat(Node->mac);
		parameters[2]=transFormat(Node->desc);
		parameters[3]=transFormat(Node->devname);
		Node->devtype=Node->devtype+'0';
		parameters[4]=transFormatInt((char *)(&Node->devtype));
		ret=sqlite_update(db, TABLE_DEV_ACCOUNT, parameters);
	}
	int i=0;
	for(i=0; i<DEVUSERCOL; i++){
		free(parameters[i]);
	}
	return ret;
}

int PMS_AccGroupUpdate(sqlite3 *db, PMS_ACCOUNT_GROUP_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_ACCOUNT_GROUP_INFO_T *Node;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((char *)(&Node->active));
		parameters[1]=transFormat(Node->name);
		parameters[2]=transFormat(Node->desc);
		ret=sqlite_update(db, TABLE_ACC_GROUP, parameters);
	}
	int i=0;
	for(i=0; i<ACCGROUPCOL; i++){
		free(parameters[i]);
	}
	return ret;
}

int PMS_DevGroupUpdate(sqlite3 *db, PMS_DEVICE_GROUP_INFO_T *head, char *reserved)
{
	char *parameters[16]={NULL};
	PMS_DEVICE_GROUP_INFO_T *Node;
	int ret=0;

	for(Node=head; Node!=NULL; Node=Node->next){
		Node->active=Node->active+'0';
		parameters[0]=transFormatInt((char *)(&Node->active));
		parameters[1]=transFormat(Node->name);
		parameters[2]=transFormat(Node->desc);
		ret=sqlite_update(db, TABLE_DEV_GROUP, parameters);
	}
	int i=0;
	for(i=0; i<DEVGROUPCOL; i++){
		free(parameters[i]);
	}
	return ret;
}

int PMS_ActionAccountInfo(int action, void *input, int flag, ...)
{
	int ret=0;
	sqlite3 *db=NULL;
	_PMS_ActionAccAPIs *APIs;
	char *str=NULL;
	char *reserved=NULL;
	va_list ap;
	//int lock=0;
	//lock=file_lock("PMS_database");

	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK){
		//file_unlock(lock);
		return  ret;
	}

	if(action == PMS_ACTION_MODIFY){
	//for modified functions
	va_start(ap, flag);
	str = va_arg(ap, char *); 
	if (str!=NULL){ 
		reserved=strdup(str);
	}else{
		reserved=NULL;
	}
	va_end(ap);
	}

	for(APIs=&AccAPIsTable[0]; APIs; APIs++)
	{
		if(action == APIs->action){
			ret=(flag)?APIs->cb_group(db, (PMS_ACCOUNT_GROUP_INFO_T *)input, reserved):APIs->cb_acc(db, (PMS_ACCOUNT_INFO_T *)input, reserved);
			if(ret!=0){
				printf("Cannot find the action funciton\n");
			}
			break;
		}
	}

	if(reserved != NULL) free(reserved);
	//file_unlock(lock);
	sqlite_close(db);
	return ret;
}

int PMS_ActionDeviceInfo(int action, void *input, int flag, ...)
{
	int ret=0;
	sqlite3 *db=NULL;
	_PMS_ActionDevAPIs *APIs;
	char *reserved=NULL, *str=NULL;
	va_list ap;
	//int lock=0;
	//lock=file_lock("PMS_database");
	
	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK){
		//file_unlock(lock);
		return  ret;
	}

	if(action == PMS_ACTION_MODIFY){
	//for modified functions
	va_start(ap, flag);
	str = va_arg(ap, char *); 
	if (str!=NULL){ 
		reserved=strdup(str);
	}else{
		reserved=NULL;
	}
	va_end(ap);
	}

	for(APIs=&DevAPIsTable[0]; APIs; APIs++)
	{
		if(action == APIs->action){
			ret=(flag)?APIs->cb_group(db, (PMS_DEVICE_GROUP_INFO_T *)input, reserved):APIs->cb_acc(db, (PMS_DEVICE_INFO_T *)input, reserved);
			if(ret!=0){
				printf("Cannot find the action funciton\n");
			}
			break;
		}
	}

	if(reserved != NULL) free(reserved);
	//file_unlock(lock);
	sqlite_close(db);
	return ret;
}


int PMS_ActAccMatchInfo(int action, int num_owned, char *input)
{
	sqlite3 *db=NULL;
	int ret=0;
	char *delm=">";
	char *parameters[32]={NULL};
	char *tmp=NULL;
	char *saveptr=NULL;

	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK)
		return  ret;

	if(action == PMS_ACTION_UPDATE){
		if(num_owned<1){
			printf("PMS_DB[%d]: Need at least names for Match table\n",__LINE__);
			ret=-1;
			goto ERR;
		}
		if ((tmp=strtok_r(input, delm, &saveptr))==NULL){
			printf("PMS_DB[%d]: No input name\n",__LINE__);
			ret=-1;
			goto ERR;
		
		}else{
		    parameters[0]=transFormat(tmp);
		    sqlite_delete(db, TABLE_USER2GROUP, parameters[0]);
		}
		while(tmp!=NULL){
			if((tmp=strtok_r(NULL, delm, &saveptr))!=NULL){
				parameters[1]=transFormat(tmp);
				ret=sqlite_update(db, TABLE_USER2GROUP, parameters);
			}	
		}
		int i=0;
		for(i=0; i<=num_owned; i++){
			free(parameters[i]);
		}
	}
ERR:
	sqlite_close(db);
	return ret;
}

int PMS_ActDevMatchInfo(int action, int num_owned, char *input)
{
	sqlite3 *db=NULL;
	int ret=0;
	char *delm=">";
	char *parameters[32]={NULL};
	char *tmp=NULL;
	char *saveptr=NULL;

	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK)
		return  ret;

	if(action == PMS_ACTION_UPDATE){
		if(num_owned<1){
			printf("PMS_DB[%d]: Need at least names for Match table\n",__LINE__);
			ret=-1;
			goto ERR;
		}
		if ((tmp=strtok_r(input, delm, &saveptr))==NULL){
			printf("PMS_DB[%d]: No input name\n",__LINE__);
			ret=-1;
			goto ERR;
		
		}else{
		    parameters[0]=transFormat(tmp);
		    sqlite_delete(db, TABLE_DEV2GROUP, parameters[0]);
		}
		while(tmp!=NULL){
			if((tmp=strtok_r(NULL, delm, &saveptr))!=NULL){
				parameters[1]=transFormat(tmp);
				ret=sqlite_update(db, TABLE_DEV2GROUP, parameters);
			}
		}
		int i=0;
		for(i=0; i<=num_owned; i++){
			free(parameters[i]);
		}
	}
ERR:
	sqlite_close(db);
	return ret;
}

int PMS_ActAccGroupMatchInfo(int action, int num_owned, char *input)
{
	sqlite3 *db=NULL;
	int ret=0;
	char *delm=">";
	char *parameters[200]={NULL};
	char *tmp=NULL;
	char *saveptr=NULL;

	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK)
		return  ret;

	if(action == PMS_ACTION_UPDATE){
		if(num_owned<1){
			printf("PMS_DB[%d]: Need at least names for Match table\n",__LINE__);
			ret=-1;
			goto ERR;
		}
		if ((tmp=strtok_r(input, delm, &saveptr))==NULL){
			printf("PMS_DB[%d]: No input name\n",__LINE__);
			ret=-1;
			goto ERR;
		
		}else{
		    parameters[0]=transFormat(tmp);
		    sqlite_delete(db, TABLE_GROUP2USER, parameters[0]);
		}
		while(tmp!=NULL){
			if((tmp=strtok_r(NULL, delm, &saveptr))!=NULL){
				parameters[1]=transFormat(tmp);
				ret=sqlite_update(db, TABLE_GROUP2USER, parameters);
			}
		}
		int i=0;
		for(i=0; i<=num_owned; i++){
			free(parameters[i]);
		}
	}
ERR:
	sqlite_close(db);
	return ret;
}
int PMS_ActDevGroupMatchInfo(int action, int num_owned, char *input)
{
	sqlite3 *db=NULL;
	int ret=0;
	char *delm=">";
	char *parameters[32]={NULL};
	char *tmp=NULL;
	char *saveptr=NULL;


	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK)
		return  ret;

	if(action == PMS_ACTION_UPDATE){
		if(num_owned<1){
			printf("PMS_DB[%d]: Need at least names for Match table\n",__LINE__);
			ret=-1;
			goto ERR;
		}
		if ((tmp=strtok_r(input, delm, &saveptr))==NULL){
			printf("PMS_DB[%d]: No input name\n",__LINE__);
			ret=-1;
			goto ERR;
		
		}else{
		    parameters[0]=transFormat(tmp);
		    sqlite_delete(db, TABLE_GROUP2DEV, parameters[0]);
		}
		while(tmp!=NULL){
			if((tmp=strtok_r(NULL, delm, &saveptr))!=NULL){
				parameters[1]=transFormat(tmp);
				ret=sqlite_update(db, TABLE_GROUP2DEV, parameters);
			}	
		}
		int i=0;
		for(i=0; i<=num_owned; i++){
			free(parameters[i]);
		}
	}
ERR:
	sqlite_close(db);
	return ret;

#if 0
	if(action == PMS_ACTION_UPDATE){ 
		parameters[0]=transFormat(para[0]);
		sqlite_delete(db, TABLE_GROUP2DEV, parameters[0]);
		do {
			parameters[1]=transFormat(para[num_input]);
			sqlite_update(db, TABLE_GROUP2DEV, parameters);
			--num_input;
		} while(num_input > 0);
		int i=0;
		for(i=0; i<num; i++){
			free(parameters[i]);
		}
	
	}
#endif
}

#if 0
int GetAccGroupMatch( PMS_ACC_GROUP_MATCH_INFO_T **input)
{

	char *errMsg = NULL;
	char **result;
	int *row, *col;
	
	PMS_ACC_GROUP_MATCH_INFO_T *tmp_input=NULL; 

	if((ret = PMS_SQLITEAPI(getTable(*db, TABLE_USER_GROUP, &row, &col, &result, "*", USER2GROUP)))!=SQLITE_OK){
			goto RET;
	}else{
		int i=1;
		for (i;i<=rows;i++) {
			if((tmp_input=PMS_list_ACCGROUPMATCH_new()) == NULL){
				ret=1;
				goto RET;
			}else{
				tmp_input->group=result[i*cols+1];
				PMS_list_SerchName(&head, tmp_input);
			}
		}
		tmp_input->owned_account_num=rows;
	}

RET:
	PMS_SQLITEAPI(close(db));
	return ret;

}
#endif

int PMS_CreateAccGroupList(PMS_ACCOUNT_GROUP_INFO_T  **head, int *num)
{
	sqlite3 *db=NULL;
	//char *errMsg = NULL;
	char **result;
	PMS_ACCOUNT_GROUP_INFO_T *tmp_input=NULL;
	PMS_ACCOUNT_GROUP_INFO_T *tmp_head=NULL;
	int ret=0;
	int cols, rows;
	
	//if((ret = PMS_SQLITEAPI(open(PMS_DB_FILE, &db, db)))!= SQLITE_OK)
	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK)
		return  ret;

	//if((ret = PMS_SQLITEAPI(getTable(db, TABLE_ACC_GROUP, &row, &col, &result, "*", 0)))!=SQLITE_OK){
	if((ret = sqlite_getTable(db, TABLE_ACC_GROUP, &rows, &cols, &result, "*", 0))!=SQLITE_OK){
		goto RET;
	}else{
		int i;
		for (i=1;i<=rows;i++) {
			if((tmp_input=PMS_list_AccountGroup_new(3, result[i*cols+0],
								   result[i*cols+1],
								   result[i*cols+2])) == NULL){
				ret=1;
				goto RET;
			}
			PMS_list_AccountGroup_add2last(&tmp_head, tmp_input);
			tmp_input->owned_account=NULL;
		}
		*num=rows;
		sqlite_freeTable(result);
		*head=tmp_head;
	}

RET:
	sqlite_close(db);
	return ret;
}

int PMS_CreateDevGroupList(PMS_DEVICE_GROUP_INFO_T  **head, int *num)
{
	sqlite3 *db=NULL;
	//char *errMsg = NULL;
	char **result;
	PMS_DEVICE_GROUP_INFO_T *tmp_input=NULL;
	PMS_DEVICE_GROUP_INFO_T *tmp_head=NULL;
	int ret=0;
	int cols, rows;
	
	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK)
		return  ret;
	

	if((ret = sqlite_getTable(db, TABLE_DEV_GROUP, &rows, &cols, &result, "*", 0))!=SQLITE_OK){
		goto RET;
	}else{
		int i;
		for (i=1;i<=rows;i++) {
			if((tmp_input=PMS_list_DeviceGroup_new(3, result[i*cols+0],
								  result[i*cols+1],
								  result[i*cols+2])) == NULL){
				ret=1;
				goto RET;
			}
			PMS_list_DeviceGroup_add2last(&tmp_head, tmp_input);
			tmp_input->owned_device=NULL;
		}
		*num=rows;
		sqlite_freeTable(result);
		*head=tmp_head;
	}

RET:
	sqlite_close(db);
	return ret;

}

int PMS_CreateAccAccountList(PMS_ACCOUNT_INFO_T  **head, int *num)
{
	sqlite3 *db=NULL;
	char **result;
	PMS_ACCOUNT_INFO_T *tmp_input=NULL;
	PMS_ACCOUNT_INFO_T *tmp_head=NULL;
	int ret=0;
	int rows, cols;

	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK){
		return ret;
	}

	if((ret = sqlite_getTable(db, TABLE_ACC_USER, &rows, &cols, &result, "*", 0))!=SQLITE_OK){
			goto RET;
	}else{
		int i;
		for (i=1;i<=rows;i++) {
			if((tmp_input=PMS_list_Account_new(cols, result[i*cols+0],
								 result[i*cols+1], 
								 result[i*cols+2], 
								 result[i*cols+3], 
								 result[i*cols+4])) == NULL){
				ret=1;
				goto RET;
			}
			PMS_list_Account_add2last(&tmp_head, tmp_input);
			tmp_input->owned_group=NULL;
		}
		*num=rows;
		sqlite_freeTable(result);
		*head=tmp_head;
	}
	
RET:
	sqlite_close(db);
	return ret;

}

int PMS_CreateDevAccountList(PMS_DEVICE_INFO_T  **head, int *num)
{
	sqlite3 *db=NULL;
	char **result;
	PMS_DEVICE_INFO_T *tmp_input=NULL;
	PMS_DEVICE_INFO_T *tmp_head=NULL;
	int ret=0;
	int rows, cols;

	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK){
		return ret;
	}

	if((ret = sqlite_getTable(db, TABLE_DEV_ACCOUNT, &rows, &cols, &result, "*", 0))!=SQLITE_OK){
			goto RET;
	}else{
		int i;
		for (i=1;i<=rows;i++) {
			if((tmp_input=PMS_list_Device_new(5, result[i*cols+0],
							     result[i*cols+1],
							     result[i*cols+2],
							     result[i*cols+3],
							     result[i*cols+4])) == NULL){
				ret=1;
				goto RET;
			}
			PMS_list_Device_add2last(&tmp_head, tmp_input);
			tmp_input->owned_group=NULL;
		}
		*num=rows;
		sqlite_freeTable(result);
		*head=tmp_head;
	}
	
RET:
	sqlite_close(db);
	return ret;
}

void *PMS_Acclist_search(PMS_ACCOUNT_INFO_T  **acc_head, PMS_ACCOUNT_GROUP_INFO_T **group_head, char *name, int flag)
{
	if(0 ==flag){
		PMS_ACCOUNT_INFO_T *tmp=*acc_head;
		while(tmp!=NULL){
			if(!strcmp(tmp->name, name))
				return (void *)tmp;
			tmp=tmp->next;
		}
	}else if ( 1 ==flag){
		PMS_ACCOUNT_GROUP_INFO_T *tmp=*group_head;
		while(tmp!=NULL){
			if(!strcmp(tmp->name, name))
				return (void *)tmp;
			tmp=tmp->next;
		}

	}else{
		return (void *)0;
	}		
	return (void *)0;
}

void *PMS_Devlist_search(PMS_DEVICE_INFO_T  **dev_head, PMS_DEVICE_GROUP_INFO_T **group_head, char *name, int flag)
{
	if(0 ==flag){
		PMS_DEVICE_INFO_T *tmp=*dev_head;
		while(tmp!=NULL){
			if(!strcmp(tmp->mac, name))
				return (void *)tmp;
			tmp=tmp->next;
		}
	}else if ( 1 ==flag){
		PMS_DEVICE_GROUP_INFO_T *tmp=*group_head;
		while(tmp!=NULL){
			if(!strcmp(tmp->name, name))
				return (void *)tmp;
			tmp=tmp->next;
		}

	}else{
		return (void *)0;
	}		
	return (void *)0;
}

//find out all accounts of each group owned
int PMS_CreateAccOwnedGroup(PMS_ACCOUNT_INFO_T  **acc_head, PMS_ACCOUNT_GROUP_INFO_T **group_head )
{
	char **result;
	int rows, cols;
	sqlite3 *db=NULL;
	PMS_ACCOUNT_GROUP_INFO_T *group_node=NULL; 
	PMS_ACCOUNT_INFO_T *acc_curr=*acc_head;
	PMS_OWNED_INFO_T *tmp_input=NULL;
	PMS_OWNED_INFO_T *owned_head=NULL;
	int ret=0;


	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK){
		return ret;
	}
	while(acc_curr!=NULL){
		owned_head=NULL;
		if((ret = sqlite_getTable(db, TABLE_USER2GROUP, &rows, &cols, &result, acc_curr->name, USER2GROUP))!=SQLITE_OK){
			goto RET;
		}else{
			int i;
			for (i=0;i<rows;i++) {
				group_node=(PMS_ACCOUNT_GROUP_INFO_T *)PMS_Acclist_search(NULL, group_head, result[i*cols+1], 1);
				if((tmp_input=PMS_list_owned_new()) == NULL){
					ret=1;
					goto RET;
				}else{
					tmp_input->member=(void *)group_node;
					tmp_input->next=NULL;
					PMS_list_Owned_add2last(&owned_head, tmp_input);
				}
			}
			sqlite_freeTable(result);
			acc_curr->owned_group=owned_head;
		}
		acc_curr=acc_curr->next;
	}
RET:
	sqlite_close(db);
	return ret;
}

//find out all accounts of each group owned
int PMS_CreateDevOwnedGroup(PMS_DEVICE_INFO_T  **dev_head, PMS_DEVICE_GROUP_INFO_T **group_head )
{
	char **result;
	int rows, cols;
	sqlite3 *db=NULL;
	PMS_DEVICE_GROUP_INFO_T *group_node=NULL; 
	PMS_DEVICE_INFO_T *dev_curr=*dev_head;
	PMS_OWNED_INFO_T *tmp_input=NULL;
	PMS_OWNED_INFO_T *owned_head=NULL;
	int ret=0;

	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK){
		return ret;
	}
	while(dev_curr!=NULL){
		owned_head=NULL;
		if((ret = sqlite_getTable(db, TABLE_DEV2GROUP, &rows, &cols, &result, dev_curr->mac, USER2GROUP))!=SQLITE_OK){
			goto RET;
		}else{
			int i;
			for (i=0;i<rows;i++) {
				group_node=(PMS_DEVICE_GROUP_INFO_T *)PMS_Devlist_search(NULL, group_head, result[i*cols+1], 1);
				if((tmp_input=PMS_list_owned_new()) == NULL){
					ret=1;
					goto RET;
				}else{
					tmp_input->member=(void *)group_node;
					tmp_input->next=NULL;
					PMS_list_Owned_add2last(&owned_head, tmp_input);
				}
			}
			sqlite_freeTable(result);
			dev_curr->owned_group=owned_head;
		}
		dev_curr=dev_curr->next;
	}
RET:
	sqlite_close(db);
	return ret;
}

//find out all accounts of each group owned
int PMS_CreateOwnedAcc(PMS_ACCOUNT_INFO_T  **acc_head, PMS_ACCOUNT_GROUP_INFO_T **group_head )
{
	int rows, cols;
	sqlite3 *db=NULL;
	PMS_ACCOUNT_INFO_T *acc_node=NULL; 
	PMS_ACCOUNT_GROUP_INFO_T *group_curr=*group_head;
	PMS_OWNED_INFO_T *tmp_input=NULL;
	PMS_OWNED_INFO_T *owned_head=NULL;
	char **result;
	int ret=0;

	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK){
		return ret;
	}
	while(group_curr!=NULL){
		owned_head=NULL;
		if((ret = sqlite_getTable(db, TABLE_USER2GROUP, &rows, &cols, &result, group_curr->name, GROUP2USER))!=SQLITE_OK){
			goto RET;
		}else{
			int i;
			for (i=0;i<rows;i++) {
				acc_node=(PMS_ACCOUNT_INFO_T *)PMS_Acclist_search(acc_head, NULL, result[i*cols+1], 0);
				if((tmp_input=PMS_list_owned_new()) == NULL){
					ret=1;
					goto RET;
				}else{
					tmp_input->member=(void *)acc_node;
					tmp_input->next=NULL;
					PMS_list_Owned_add2last(&owned_head, tmp_input);
				}
			}
			sqlite_freeTable(result);
			group_curr->owned_account=owned_head;
		}
		group_curr=group_curr->next;
	}
RET:
	sqlite_close(db);
	return ret;
}

//find out all accounts of each group owned
int PMS_CreateOwnedDev(PMS_DEVICE_INFO_T  **dev_head, PMS_DEVICE_GROUP_INFO_T **group_head )
{
	int rows, cols;
	sqlite3 *db=NULL;
	PMS_DEVICE_INFO_T *dev_node=NULL; 
	PMS_DEVICE_GROUP_INFO_T *group_curr=*group_head;
	PMS_OWNED_INFO_T *tmp_input=NULL;
	PMS_OWNED_INFO_T *owned_head=NULL;
	char **result;
	int ret=0;

	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK){
		return ret;
	}
	while(group_curr!=NULL){
		owned_head=NULL;
		if((ret = sqlite_getTable(db, TABLE_DEV2GROUP, &rows, &cols, &result, group_curr->name, GROUP2USER))!=SQLITE_OK){
			goto RET;
		}else{
			int i;
			for (i=0;i<rows;i++) {
				dev_node=(PMS_DEVICE_INFO_T *)PMS_Devlist_search(dev_head, NULL, result[i*cols+1], 0);
				if((tmp_input=PMS_list_owned_new()) == NULL){
					ret=1;
					goto RET;
				}else{
					tmp_input->member=(void *)dev_node;
					tmp_input->next=NULL;
					PMS_list_Owned_add2last(&owned_head, tmp_input);
				}
			}
			sqlite_freeTable(result);
			group_curr->owned_device=owned_head;
		}
		group_curr=group_curr->next;
	}
RET:
	sqlite_close(db);
	return ret;
}

int PMS_GetAccAllInfo(PMS_ACCOUNT_INFO_T ***input_acc, PMS_ACCOUNT_GROUP_INFO_T ***input_group, int **acc_num, int **group_num)
{
	int ret=0;
	PMS_ACCOUNT_INFO_T *acc_head=NULL;
	PMS_ACCOUNT_GROUP_INFO_T *acc_group_head=NULL;
	int accountNum=0, groupNum=0;

	ret|=PMS_CreateAccAccountList(&acc_head, &accountNum);
	ret|=PMS_CreateAccGroupList(&acc_group_head, &groupNum);
	ret|=PMS_CreateAccOwnedGroup(&acc_head, &acc_group_head);
	ret|=PMS_CreateOwnedAcc(&acc_head, &acc_group_head);
	
#if 0
	PMS_ACCOUNT_GROUP_INFO_T *follow_group=acc_group_head;
	for(follow_group = acc_group_head; follow_group != NULL; follow_group = follow_group->next){
		printf("%d\t   %d\t   %s\n", follow_group->index, follow_group->active, follow_group->name);
		
		PMS_OWNED_INFO_T *owned_account=follow_group->owned_account;
		while(owned_account!=NULL){
			PMS_ACCOUNT_INFO_T *Account_owned=(PMS_ACCOUNT_INFO_T *)owned_account->member;
			printf("Owned Account: %s\t", Account_owned->name);
			owned_account=owned_account->next;
		}
		printf("\n");
	}
#endif

	**input_acc=acc_head;
	**acc_num=accountNum;
	**input_group=acc_group_head;
	**group_num=groupNum;

	return ret;
}

int PMS_GetDevAllInfo(PMS_DEVICE_INFO_T ***input_dev, PMS_DEVICE_GROUP_INFO_T ***input_group, int **dev_num, int **group_num)
{
	int ret=0;
	PMS_DEVICE_INFO_T *dev_head=NULL;
	PMS_DEVICE_GROUP_INFO_T *dev_group_head=NULL;
	int accountNum=0, groupNum=0;

	ret|=PMS_CreateDevAccountList(&dev_head, &accountNum);
	ret|=PMS_CreateDevGroupList(&dev_group_head, &groupNum);
	ret|=PMS_CreateDevOwnedGroup(&dev_head, &dev_group_head);
	ret|=PMS_CreateOwnedDev(&dev_head, &dev_group_head);
	
#if 0
	PMS_ACCOUNT_GROUP_INFO_T *follow_group=acc_group_head;
	for(follow_group = acc_group_head; follow_group != NULL; follow_group = follow_group->next){
		printf("%d\t   %d\t   %s\n", follow_group->index, follow_group->active, follow_group->name);
		
		PMS_OWNED_INFO_T *owned_account=follow_group->owned_account;
		while(owned_account!=NULL){
			PMS_ACCOUNT_INFO_T *Account_owned=(PMS_ACCOUNT_INFO_T *)owned_account->member;
			printf("Owned Account: %s\t", Account_owned->name);
			owned_account=owned_account->next;
		}
		printf("\n");


	}
#endif
	**input_dev=dev_head;
	**dev_num=accountNum;
	**input_group=dev_group_head;
	**group_num=groupNum;

	return ret;
}


int PMS_GetAccountInfo(int action, PMS_ACCOUNT_INFO_T **input_acc, PMS_ACCOUNT_GROUP_INFO_T **input_group, int *acc_num, int *group_num)
{
	int ret=0;

	if(action == PMS_ACTION_GET_FULL){
		ret=PMS_GetAccAllInfo(&input_acc, &input_group, &acc_num, &group_num);
		if (ret == 0){
			return 0;
		}else
			return -1;
	}else{
		return 0;
	}

}

int PMS_GetDeviceInfo(int action, PMS_DEVICE_INFO_T **input_dev, PMS_DEVICE_GROUP_INFO_T **input_group, int *dev_num, int *group_num)
{
	int ret=0;

	if(action == PMS_ACTION_GET_FULL){
		ret=PMS_GetDevAllInfo(&input_dev, &input_group, &dev_num, &group_num);
		if (ret == 0){
			return 0;
		}else
			return -1;
	}else{
		return 0;
	}
}
void recursive_mkdir(char *start, char *end)
{
	char *tmp_end=end;
	DIR *ret;
	if((ret=opendir(start))== NULL){
		while(*--tmp_end!='/')
			if(tmp_end == start) return ;
		*tmp_end='\0';
		recursive_mkdir(start, tmp_end);
		*tmp_end='/';
		mkdir(start, 0777);
	}else{
		closedir(ret);
		return;
	}
	return;
}

void checkDir()
{
	int len=0;
	char tmp[128];
	char *last_chr=NULL, *chr_ptr=NULL;
	int count=0;

	len=strlen(PMS_DB_FILE);
	memset(tmp, 0, sizeof(tmp));
	strcpy(tmp, PMS_DB_FILE);
	chr_ptr=tmp+len;

	while(count < 2 ){
		if (last_chr == tmp) return;
		if ('/'==(*chr_ptr--)){
			if(count == 0) last_chr=chr_ptr+1;
			count++;
		}
	}
	*last_chr='\0';
	recursive_mkdir(tmp, last_chr);

	return;
}

int PMS_CreateAllTables()
{
	sqlite3 *db=NULL;
	int ret=0;

	checkDir();
	
	if((ret = sqlite_open(PMS_DB_FILE, &db, db))!= SQLITE_OK){
		return ret;
	}
	 
	if ((ret = sqlite_create(db)) != SQLITE_OK){
		goto RET;
	}   

	sqlite_close(db);
RET:
	sqlite_close(db);
	return ret;
}



void PMS_FreeAccInfo(PMS_ACCOUNT_INFO_T **acc_head, PMS_ACCOUNT_GROUP_INFO_T **group_head)
{
	PMS_list_ACCOUNT_free(*acc_head);
	PMS_list_ACCOUNT_GROUP_free(*group_head);
}

void PMS_FreeDevInfo(PMS_DEVICE_INFO_T **dev_head, PMS_DEVICE_GROUP_INFO_T **group_head)
{
	PMS_list_DEVICE_free(*dev_head);
	PMS_list_DEVICE_GROUP_free(*group_head);
}

