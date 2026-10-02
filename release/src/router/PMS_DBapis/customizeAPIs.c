#include <PMS_DBAPIs.h>

static char *createsql_acc_user = "CREATE TABLE IF NOT EXISTS User("
			 "Active INTEGER NOT NULL,"
			 "Name VARCHAR NOT NULL UNIQUE,"
			 "Passwd TEXT NOT NULL,"
			 "Desc TEXT,"
			 "Email TEXT);";

static char *createsql_acc_group = "CREATE TABLE IF NOT EXISTS User_group("
			 "Active INTEGER NOT NULL,"
			 "Name TEXT NOT NULL UNIQUE,"
			 "Desc TEXT);";

static char *createsql_dev_user = "CREATE TABLE IF NOT EXISTS Device("
			 "Active INTEGER NOT NULL,"
			 "MAC VARCHAR NOT NULL UNIQUE,"
			 "Desc TEXT,"
			 "DevName TEXT,"
			 "DevType INTEGER NOT NULL default '0');";

static char *createsql_dev_group = "CREATE TABLE IF NOT EXISTS Device_group("
			"Active INTEGER NOT NULL,"
			 "Name TEXT NOT NULL UNIQUE,"
			 "Desc TEXT);";

static char *createsql_user_group = "CREATE TABLE IF NOT EXISTS User2Group("
			 "userName TEXT NOT NULL,"
			 "groupName TEXT NOT NULL)";

static char *createsql_mac_group = "CREATE TABLE IF NOT EXISTS Dev2Group("
			 "devName TEXT NOT NULL,"
			 "groupName TEXT NOT NULL)";

const char UserStr[][32]={"UPDATE User set", "Active", "Name", "Passwd", "Desc", "Email", "Name"};
const char DevStr[][32]={"UPDATE Device set", "Active", "MAC", "Desc", "DevName", "DevType", "MAC"};
const char UserGroupStr[][32]={"UPDATE User_group set", "Active", "Name", "Desc", "Name"};
const char DevGroupStr[][32]={"UPDATE Device_group set", "Active", "Name", "Desc", "Name"};

void my_sprintf(char *Str, char *para[], int count, char *srcName, const char strTab[][32])
{
	int i=0;
	char *tmp=Str;
	int len=0;
	strcpy(tmp, strTab[0]);
	tmp=tmp+strlen(strTab[0]);
	len=256-strlen(Str);
	
	for(i=1; i<=count;i++)
	{
		if(para[i-1]!=NULL && strcmp(para[i-1], "NULL")){
			snprintf(tmp, len," %s=%s,", strTab[i], para[i-1]);
			tmp=tmp+strlen(strTab[i])+strlen(para[i-1])+3;
			len=256-strlen(Str);
		}
	}		
	snprintf(tmp-1, len, " where %s=%s;", strTab[i], srcName);
}



int sqlite_getTable(sqlite3 *db, int table, int *row, int *col, char ***result, char *Name, int flag)
{
	char sql_str[128];
	char *errMsg=NULL;
	int ret=0;
	
	//char *key="12345";
	//sqlite3_key(db, key, sizeof(key));

	switch (table){
		case  TABLE_ACC_USER:
			if(!strcmp(Name, "*")){
				snprintf(sql_str, sizeof(sql_str),"%s", "SELECT * from User");
			}else{
				snprintf(sql_str, sizeof(sql_str),"SELECT * from User where Name='%s'", Name);
			}		
			break;
		case  TABLE_ACC_GROUP:
			if(!strcmp(Name, "*")){
				snprintf(sql_str, sizeof(sql_str), "%s", "SELECT * from User_group");
			}else{
				snprintf(sql_str, sizeof(sql_str), "SELECT * from User_group where Name='%s'", Name);
			}		
			break;
		case  TABLE_DEV_ACCOUNT:
			if(!strcmp(Name, "*")){
				snprintf(sql_str, sizeof(sql_str), "%s", "SELECT * from Device;");
			}else{
				snprintf(sql_str, sizeof(sql_str),"SELECT * from Device where MAC='%s'", Name);
			}
			break;
		case  TABLE_DEV_GROUP: 
			if(!strcmp(Name, "*")){
				snprintf(sql_str, sizeof(sql_str), "%s", "SELECT * from Device_group;");
			}else{
				snprintf(sql_str, sizeof(sql_str), "SELECT * from Device_group where Name='%s'", Name);
			}
			break;
		case  TABLE_USER2GROUP: 
			if(!strcmp(Name, "*")){
				snprintf(sql_str, sizeof(sql_str), "%s", "SELECT * from User2Group;");
			}else{
				if (flag == USER2GROUP){
					snprintf(sql_str, sizeof(sql_str),"SELECT Name from User_group where Name IN (SELECT groupName from User2Group WHERE userName='%s')", Name);
				}else if (flag == GROUP2USER){
					snprintf(sql_str, sizeof(sql_str),"SELECT Name from User where Name IN (SELECT userName from User2Group WHERE groupName='%s')", Name);
				}else {
				}
			}
			break;
		case  TABLE_DEV2GROUP: 
			if(!strcmp(Name, "*")){
				snprintf(sql_str, sizeof(sql_str), "%s", "SELECT * from Dev2Group;");
			}else{
				if (flag == USER2GROUP){
					snprintf(sql_str, sizeof(sql_str), "SELECT Name from Device_group where Name IN (SELECT groupName from Dev2Group WHERE devName='%s')", Name);
				}else if (flag == GROUP2USER){
					snprintf(sql_str, sizeof(sql_str), "SELECT MAC from Device where MAC IN (SELECT devName from Dev2Group WHERE groupName='%s')", Name);
				}else {
				}
			}
			break;
		case  TABLE_SERVICES:
			break;
		default:
			break;
	}

	ret=sqlite3_get_table(db, sql_str, result, row, col, &errMsg);
	if(errMsg!=NULL){
		printf("SQL error: %s\n", sqlite3_errmsg (db));  
		sqlite3_free(errMsg);
	}
	return ret;
}

void sqlite_freeTable(char **result)
{
	sqlite3_free_table(result);
	return;
}

int sqlite_modify(sqlite3 *db, int table, char *para[], char *srcName)
{
	char sql_str[256];
	char sql_str1[256];
	int ret=0;
	char *errMsg=NULL;
	//char *key="12345";
	//sqlite3_key(db, key, sizeof(key));

	switch (table){
		case  TABLE_ACC_USER:
			my_sprintf(sql_str, para, 5, srcName, UserStr);
			snprintf(sql_str1, sizeof(sql_str1), "UPDATE User2Group set userName=%s where userName=%s;",
				para[1], srcName);
			break;
		case  TABLE_ACC_GROUP:
			my_sprintf(sql_str, para, 3, srcName, UserGroupStr);
			snprintf(sql_str1, sizeof(sql_str1), "UPDATE User2Group set groupName=%s where groupName=%s;",
				para[1], srcName);
			break;
		case  TABLE_DEV_ACCOUNT:
			my_sprintf(sql_str, para, 5, srcName, DevStr);
			snprintf(sql_str1, sizeof(sql_str1), "UPDATE Dev2Group set devName=%s where devName=%s;",
				para[1], srcName);
			break;
		case  TABLE_DEV_GROUP: 
			my_sprintf(sql_str, para, 3, srcName, DevGroupStr);
			snprintf(sql_str1, sizeof(sql_str1), "UPDATE Dev2Group set groupName=%s where groupName=%s;",
				para[1], srcName);
			break;
		case  TABLE_USER2GROUP: 
			snprintf(sql_str, sizeof(sql_str), "UPDATE User2Group set userName=%s where userName=%s;",
				para[0], srcName);
			break;
		case  TABLE_GROUP2USER: 
			snprintf(sql_str, sizeof(sql_str), "UPDATE User2Group set groupName=%s where groupName=%s;",
				para[1], srcName);
			break;
		case  TABLE_DEV2GROUP: 
			snprintf(sql_str, sizeof(sql_str), "UPDATE Dev2Group set devName=%s where devName=%s;",
				para[0], srcName);
			break;
		case  TABLE_GROUP2DEV: 
			snprintf(sql_str, sizeof(sql_str), "UPDATE Dev2Group set groupName=%s where groupName=%s;",
				para[1], srcName);
			break;
		default:
			break;
	}
	ret=sqlite3_exec(db, sql_str1, 0, 0, &errMsg);
	ret|=sqlite3_exec(db, sql_str, 0, 0, &errMsg);

	if(errMsg!=NULL)
		sqlite3_free(errMsg);

	return ret;
}



int sqlite_update(sqlite3 *db, int table, char *para[])
{
	char sql_str[256];
	int ret=0;
	char *errMsg=NULL;
	//char *key="12345";
	//sqlite3_key(db, key, sizeof(key));

	switch (table){
		case  TABLE_ACC_USER:
			snprintf(sql_str, sizeof(sql_str), "REPLACE INTO User VALUES(%d, %s, %s, %s, %s);",
				atoi(para[0]), para[1], para[2], para[3], para[4]);
			break;
		case  TABLE_ACC_GROUP:
			snprintf(sql_str, sizeof(sql_str), "REPLACE INTO User_group VALUES(%d, %s, %s);",
				atoi(para[0]), para[1], para[2]);
			break;
		case  TABLE_DEV_ACCOUNT:
			snprintf(sql_str, sizeof(sql_str), "REPLACE INTO Device VALUES(%d, %s, %s, %s, %d);",
				atoi(para[0]), para[1], para[2], para[3], atoi(para[4]));
			break;
		case  TABLE_DEV_GROUP: 
			snprintf(sql_str, sizeof(sql_str), "REPLACE INTO Device_group VALUES(%d, %s, %s);",
				atoi(para[0]), para[1], para[2]);
			break;
		case  TABLE_USER2GROUP: 
			snprintf(sql_str, sizeof(sql_str), "INSERT INTO User2Group VALUES(%s, %s);",
				para[0], para[1]);
			break;
		case  TABLE_GROUP2USER: 
			snprintf(sql_str, sizeof(sql_str), "INSERT INTO User2Group VALUES(%s, %s);",
				para[1], para[0]);
			break;
		case  TABLE_DEV2GROUP: 
			snprintf(sql_str, sizeof(sql_str), "INSERT INTO Dev2Group VALUES(%s, %s);",
				para[0], para[1]);
			break;
		case  TABLE_GROUP2DEV: 
			snprintf(sql_str, sizeof(sql_str), "INSERT INTO Dev2Group VALUES(%s, %s);",
				para[1], para[0]);
			break;
		default:
			break;
	}
	ret=sqlite3_exec(db, sql_str, 0, 0, &errMsg);

	if(errMsg!=NULL)
		sqlite3_free(errMsg);

	return ret;
}

int sqlite_delete(sqlite3 *db, int table, char *Name)
{
	char sql_str[256];
	char sql_str1[256];
	int ret=0;
	char *errMsg=NULL;
	
	//char *key="12345";
	//sqlite3_key(db, key, sizeof(key));

	switch (table){
		case  TABLE_ACC_USER:
			snprintf(sql_str, sizeof(sql_str), "DELETE from User WHERE Name=%s;", Name);
			snprintf(sql_str1, sizeof(sql_str1), "DELETE from  User2Group WHERE userName=%s;", Name);
			break;
		case  TABLE_ACC_GROUP:
			snprintf(sql_str, sizeof(sql_str), "DELETE from User_group WHERE Name=%s;", Name);
			snprintf(sql_str1, sizeof(sql_str1), "DELETE from  User2Group WHERE groupName=%s;", Name);
			break;
		case  TABLE_DEV_ACCOUNT:
			snprintf(sql_str, sizeof(sql_str), "DELETE from Device WHERE MAC=%s;", Name);
			snprintf(sql_str1, sizeof(sql_str1), "DELETE from  Dev2Group WHERE devName=%s;", Name);
			break;
		case  TABLE_DEV_GROUP: 
			snprintf(sql_str, sizeof(sql_str), "DELETE from Device_group WHERE Name=%s;", Name);
			snprintf(sql_str1, sizeof(sql_str1), "DELETE from  Dev2Group WHERE groupName=%s;", Name);
			break;
		case  TABLE_USER2GROUP: 
			snprintf(sql_str, sizeof(sql_str), "DELETE from  User2Group WHERE userName=%s;", Name);
			break;
		case  TABLE_GROUP2USER: 
			snprintf(sql_str, sizeof(sql_str), "DELETE from  User2Group WHERE groupName=%s;", Name);
			break;
		case  TABLE_DEV2GROUP: 
			snprintf(sql_str, sizeof(sql_str), "DELETE from  Dev2Group WHERE devName=%s;", Name);
			break;
		case  TABLE_GROUP2DEV: 
			snprintf(sql_str, sizeof(sql_str), "DELETE from  Dev2Group WHERE groupName=%s;", Name);
			break;

		case  TABLE_SERVICES:
			break;
		default:
			break;
	}
	ret=sqlite3_exec(db, sql_str, 0, 0, &errMsg);
	if(strlen(sql_str1) >0 ){
		ret|=sqlite3_exec(db, sql_str1, 0, 0, &errMsg);
	}

	if(errMsg!=NULL)
		sqlite3_free(errMsg);

	return ret;
}


int sqlite_create(sqlite3 *db)
{
	int ret=0;
	char *errMsg=NULL;
	
	//char *key="12345";
	//sqlite3_key(db, key, sizeof(key));

	//sqlite3_exec(db, enable_foreign, 0, 0, &errMsg);
	ret|=sqlite3_exec(db, createsql_acc_user, 0, 0, &errMsg);
	ret|=sqlite3_exec(db, createsql_acc_group, 0, 0, &errMsg);
	ret|=sqlite3_exec(db, createsql_dev_user, 0, 0, &errMsg);
	ret|=sqlite3_exec(db, createsql_dev_group, 0, 0, &errMsg);
	ret|=sqlite3_exec(db, createsql_user_group, 0, 0, &errMsg);
	ret|=sqlite3_exec(db, createsql_mac_group, 0, 0, &errMsg);

	if(errMsg!=NULL)
		sqlite3_free(errMsg);

	return ret;
}

int sqlite_open(char *path, sqlite3 **db, sqlite3 *db_key)
{
	int ret=0;
	if(path == NULL)
		return -1;
	//char *key="12345";
	ret= sqlite3_open_v2(path, db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	//sqlite3_key(db_key, key, sizeof(key));
	return ret;
}

int sqlite_close(sqlite3 *db)
{
	int ret=0;
	//ret= sqlite3_close_v2(db);
	ret= sqlite3_close(db);
	return ret;
}

