
#include <wb.h>					// include the header of web service 
#include <wb_util.h>
#include <curl_api.h>
//#include <wb_test_profile.h>
#include <openssl/md5.h>
#include <ssl_api.h>
#include <log.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "parse_xml.h"
#include "parse_json.h"
#define WB_DBG 1

#define DM_RETRY_COUNT 6

char wb_custom_header[256];

const aae_status_t aae_status_list[] ={
	{0,		"Success"},
	{1,		"Authentication Fail"},
	{2,		"Invalid Service ID"},
	{3,		"No Device Exist"},
	{4,		"No Right"},
	{5, 	"No User Exist"},
	{6, 	"Service error"},
	{7, 	"Invalid xml document"},
	{8, 	"Database error"},
	{9, 	"Specific service devices is already full"},
	{10,	"Unsupported Area"},
	{11,	"Apple/Google notification service fail"},
	{12,	"This account already registered"},
	{13,	"Asus web storage service error"},
	{-1,	NULL}
};

char *get_curl_status_string(int status)
{
	char *curl_status_str = curl_get_status_string(status);
	return !strcmp(curl_status_str, "No error") ? "Success" : curl_status_str;
}

char *get_aae_status_string(int status)
{
    const aae_status_t *aae_status = aae_status_list;
    for (; aae_status->status != -1; aae_status++) {
        if (aae_status->status == status) {
            return aae_status->status_text;
        }
    }
    return "Unknown Error";
}

#define get_append_data(...) make_str(__VA_ARGS__)
int 	proc_getservicearea_xml(const char* name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{		
	if(!name || !value || !data_struct) return -1;
	//printf("name <%s> ,value <%s>\n", name, value);
	GetServiceArea* pgsa = (GetServiceArea*)data_struct;	
	#define TEMP_SIZE 128
	//char 	valuetmp[TEMP_SIZE] ={0};
	//memcpy(valuetmp,"value", value );	

	if(!strcmp(name, "status")) {
		snprintf(pgsa->status, sizeof(pgsa->status), "%s", value);
	}else if(!strcmp(name, "servicearea")){
		snprintf(pgsa->servicearea, sizeof(pgsa->servicearea), "%s", value);
	}else if(!strcmp(name, "time")){
		snprintf(pgsa->time, sizeof(pgsa->time), "%s", value);
	}else if(!strcmp(name, "srcip")){
		snprintf(pgsa->srcip, sizeof(pgsa->srcip), "%s", value);
	}else if(!strcmp(name, "retrytime")){
		snprintf(pgsa->retrytime, sizeof(pgsa->retrytime), "%s", value);
	}else {
		Cdbg(WB_DBG,"error: unknow tag <%s>, unkonow value <%s>", name, value);
	}
	return 0;
}
//
// charles test variable cnt
//int cnt=0;
//
int	set_srv_name(const char* ip, const char* srv_type, Login* login)
{
	SrvInfo *p =NULL ;

	if(!strcmp(srv_type, "relayinfo"))
		p = login->relayinfoList;
	if(!strcmp(srv_type, "stuninfo"))
		p = login->stuninfoList;
	if(!strcmp(srv_type, "turninfo"))
		p = login->turninfoList;
	if(!strcmp(srv_type, "pnsinfo"))
		p = login->pnsinfoList;
	if(!strcmp(srv_type, "psrinfo"))
		p = login->psrinfoList;
	if(!strcmp(srv_type, "webstorageinfo"))
		p = login->webstorageinfoList;
	if(!strcmp(srv_type, "ddnsinfo"))
		p = login->ddnsinfoList;
	//Cdbg(WB_DBG,"ip=%s, srv_type=%s, p =%p, login=%p", ip, srv_type, p, login);
	Cdbg(WB_DBG, "ri =%p, si=%p, ti=%p", login->relayinfoList, login->stuninfoList, login->turninfoList);
	if(!p){
		p = (SrvInfo*)malloc(sizeof(SrvInfo)); memset(p, 0 , sizeof(SrvInfo));
		Cdbg(WB_DBG, "p =%p, p->next=%p", p, p->next);
		snprintf(p->srv_ip, sizeof(p->srv_ip), "%s", ip);
		if(!strcmp(srv_type, "relayinfo"))
			login->relayinfoList = p;
		if(!strcmp(srv_type, "stuninfo"))
			login->stuninfoList = p;
		if(!strcmp(srv_type, "turninfo"))
			login->turninfoList = p;
		if(!strcmp(srv_type, "pnsinfo"))
			login->pnsinfoList = p;
		if(!strcmp(srv_type, "psrinfo"))
			login->psrinfoList = p;
		if(!strcmp(srv_type, "webstorageinfo"))
			login->webstorageinfoList = p;
		if(!strcmp(srv_type, "ddnsinfo"))
			login->ddnsinfoList = p;
	}else{
		while(p){
			Cdbg(WB_DBG, "p =%p, p->next=%p", p , p->next);
			if(!p->next) {
				p->next =(SrvInfo*) malloc(sizeof(SrvInfo));
				memset(p->next, 0, sizeof(SrvInfo));
				snprintf(p->next->srv_ip, sizeof(p->next->srv_ip), "%s", ip);
				break;
			}
			p= p->next;
		}
	}
	return 0;
}

int 	proc_login_xml(const char* name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{
	if(!name || !value || !data_struct) return -1;

	Login* login = (Login*)data_struct;	
	if(!strcmp(name, "status")) {
		snprintf(login->status, sizeof(login->status), "%s", value);
	}else if(!strcmp(name, "apilevel_status")) {
		snprintf(login->apilevel_status, sizeof(login->apilevel_status), "%s", value);
	}else if(!strcmp(name, "apilevel")) {
		snprintf(login->apilevel, sizeof(login->apilevel), "%s", value);
	}else if(!strcmp(name, "usersvclevel")) {
		snprintf(login->usersvclevel, sizeof(login->usersvclevel), "%s", value);
	}else if(!strcmp(name, "cusid")) {
		snprintf(login->cusid, sizeof(login->cusid), "%s", value);
	}else if(!strcmp(name, "userticket")) {
		snprintf(login->userticket, sizeof(login->userticket), "%s", value);
	}else if(!strcmp(name, "userrefreshticket")) {
		snprintf(login->userrefreshticket, sizeof(login->userrefreshticket), "%s", value);
	}else if(!strcmp(name, "ssoflag")) {
		snprintf(login->ssoflag, sizeof(login->ssoflag), "%s", value);
	}else if(!strcmp(name, "usernickname")) {
		snprintf(login->usernickname, sizeof(login->usernickname), "%s", value);
	}else if(!strcmp(name, "deviceid")) {
		snprintf(login->deviceid, sizeof(login->deviceid), "%s", value);
	}else if(!strcmp(name, "deviceticket")) {
		snprintf(login->deviceticket, sizeof(login->deviceticket), "%s", value);
	}else if(!strcmp(name, "relayinfo")) {
		set_srv_name(value, name, login);
	}else if(!strcmp(name, "stuninfo")) {
		set_srv_name(value, name, login);
	}else if(!strcmp(name, "turninfo")) {
		set_srv_name(value, name, login);
	}else if(!strcmp(name, "pnsinfo")) {
		set_srv_name(value, name, login);
	}else if(!strcmp(name, "psrinfo")) {
		set_srv_name(value, name, login);
	}else if(!strcmp(name, "webstorageinfo")) {
		set_srv_name(value, name, login);
	}else if(!strcmp(name, "ddnsinfo")) {
		set_srv_name(value, name, login);
	}else if(!strcmp(name, "deviceticketexpiretime")) {
		snprintf(login->deviceticketexpiretime, sizeof(login->deviceticketexpiretime), "%s", value);
	}else if(!strcmp(name, "time")) {
		snprintf(login->time, sizeof(login->time), "%s", value);
	}else{
		Cdbg(WB_DBG,"error: unknow tag <%s>, unkonow value <%s>", name, value);
	}
	return 0;
}

int proc_set_friend_list(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{
	if(!feild_name || !value || !data_struct) return -1;
	Cdbg(WB_DBG, "****************** feild_name=%s",feild_name );
	Cdbg(WB_DBG, "****************** value=%s",value );
	Cdbg(WB_DBG, "****************** data structure=%p",data_struct );
	
	Friends* pF = (Friends*)data_struct;
	// no friend profile save in the list,
	// create first node of list.
	size_t len = strlen(value)+1;
	if(!strcmp(feild_name, "userid")){
		snprintf(pF->userid, sizeof(pF->userid), "%s", value);
	}else if(!strcmp(feild_name, "cusid")){
		snprintf(pF->cusid, sizeof(pF->cusid), "%s", value);
	}else if(!strcmp(feild_name, "nickname")){
		snprintf(pF->nickname, sizeof(pF->nickname), "%s", value);
	}else{

	}
		
	return 0;
}

int proc_queryfriend_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{		
	if(!feild_name || !value || !data_struct) return -1;
	QueryFriend* pQF = (QueryFriend*)data_struct;
	if(!strcmp(feild_name, "friend")) {
		// go to parse
		//parse_node(xml_buff, wm->ws_storage, wm->ws_storage_size, &proc);	
		PROC_XML_DATA proc =proc_set_friend_list;	  	  	
		size_t fd_struct_size = sizeof(Friends);
		pFriends pF = (pFriends)malloc(fd_struct_size);
		memset(pF, 0, fd_struct_size);
		parse_child_node(xmldata, pF, proc);
		if(pQF->FriendList){
			pFriends p= pQF->FriendList;
			while(p){
				if(!p->next){
					Cdbg(WB_DBG,"break.......");
					p->next = pF;
					break;
				}
				p = p->next;
			}
		}else{
			pQF->FriendList = pF;
		}
	}else if(!strcmp(feild_name, "status")){
		snprintf(pQF->status, sizeof(pQF->status), "%s", value);
	}else if(!strcmp(feild_name, "time")){
		snprintf(pQF->time, sizeof(pQF->time), "%s", value);
	}else{

	}
	return 0;
}

int proc_set_profile_list(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{
	Cdbg(WB_DBG, "start...");
	if(!feild_name || !value || !data_struct) return -1;
	Profile* pF = (Profile*)data_struct;
	size_t len = strlen(value)+1;
	if(!strcmp(feild_name, "deviceid")){
		snprintf(pF->deviceid, sizeof(pF->deviceid), "%s", value);
	}else if(!strcmp(feild_name, "devicestatus")){
		snprintf(pF->devicestatus, sizeof(pF->devicestatus), "%s", value);
	}else if(!strcmp(feild_name, "devicename")){
		snprintf(pF->devicename, sizeof(pF->devicename), "%s", value);
	}else if(!strcmp(feild_name, "deviceservice")){
		snprintf(pF->deviceservice, sizeof(pF->deviceservice), "%s", value);
	}else if(!strcmp(feild_name, "devicenat")){
		snprintf(pF->devicenat, sizeof(pF->devicenat), "%s", value);
	}else if(!strcmp(feild_name, "devicedesc")){
		snprintf(pF->devicedesc, sizeof(pF->devicedesc), "%s", value);
	}else{

	}
	Cdbg(WB_DBG, "end...");
	return 0;
}

int 	proc_listprofile_xml(const char* feild_name,const  char* value , void* data_struct, XML_DATA_ * xmldata)
{	
	Cdbg(WB_DBG, "start... name=%s", feild_name);
	if(!feild_name || !value || !data_struct) return -1;
	ListProfile* lpf = (ListProfile*)data_struct;
	if(!strcmp(feild_name, "status") ){
		snprintf(lpf->status, sizeof(lpf->status), "%s", value);
	}else if(!strcmp(feild_name, "time")){
		snprintf(lpf->time, sizeof(lpf->time), "%s", value);
	}else if(!strcmp(feild_name, "profile")){
		PROC_XML_DATA proc =proc_set_profile_list;	  	  	
		size_t pf_struct_size = sizeof(Profile);
		pProfile pF = (pProfile)malloc(pf_struct_size);
		memset(pF, 0, pf_struct_size);
		parse_child_node(xmldata, pF, proc);
		Cdbg(WB_DBG, "loop profile list");
		if(lpf->pProfileList){
		Cdbg(WB_DBG, " profile list =%p", lpf->pProfileList);
			pProfile p= lpf->pProfileList;
			while(p){
				if(!p->next){
					Cdbg(WB_DBG,"break.......");
					p->next = pF;
					break;
				}
				p = p->next;
			}
		}else{
		Cdbg(WB_DBG, " no profile list ");
			lpf->pProfileList = pF;
		}
	
	}else{

	}
	Cdbg(WB_DBG, "end...");
	return 0;
}

int 	proc_updateprofile_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{	
	//Cdbg(WB_DBG, "start... name=%s, value=%s", feild_name, value);
	UpdateProfile * pup = (UpdateProfile*)data_struct;
	if(!strcmp(feild_name, "status") ){
		snprintf(pup->status, sizeof(pup->status), "%s", value);
	}else if(!strcmp(feild_name, "deviceticketexpiretime")){
		snprintf(pup->deviceticketexpiretime, sizeof(pup->deviceticketexpiretime), "%s", value);
	}else if(!strcmp(feild_name, "time")){
		snprintf(pup->time, sizeof(pup->time), "%s", value);
	}else{

	}
	Cdbg(WB_DBG, "end");
	return 0;
}

int 	proc_logout_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{	
	Logout* plgo = (Logout*)data_struct;
	if(!strcmp(feild_name, "status") ){
		snprintf(plgo->status, sizeof(plgo->status), "%s", value);
	}else if(!strcmp(feild_name, "time")){
		snprintf(plgo->time, sizeof(plgo->time), "%s", value);
	}else{

	}
	Cdbg(WB_DBG, "end");
	return 0;
}

int 	proc_getwebpath_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{	
	return 0;
}

int 	proc_createpin_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{	
	CreatePin* pcp = (CreatePin*)data_struct;
	if(!strcmp(feild_name, "status") ){
		snprintf(pcp->status, sizeof(pcp->status), "%s", value);
	}else if(!strcmp(feild_name, "time")){
		snprintf(pcp->time, sizeof(pcp->time), "%s", value);
	}else if(!strcmp(feild_name, "pin")){
		snprintf(pcp->pin, sizeof(pcp->pin), "%s", value);
	}else if(!strcmp(feild_name, "deviceticketexpiretime")){
		snprintf(pcp->deviceticketexpiretime, sizeof(pcp->deviceticketexpiretime), "%s", value);
	}else{

	}
	Cdbg(WB_DBG, "end");

	return 0;
}

int 	proc_querypin_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{	
	QueryPin* pqp = (QueryPin*)data_struct;
	if(!strcmp(feild_name, "status") ){
		snprintf(pqp->status, sizeof(pqp->status), "%s", value);
	}else if(!strcmp(feild_name, "deviceid")){
		snprintf(pqp->deviceid, sizeof(pqp->deviceid), "%s", value);
	}else if(!strcmp(feild_name, "devicestatus")){
		snprintf(pqp->devicestatus, sizeof(pqp->devicestatus), "%s", value);
	}else if(!strcmp(feild_name, "devicename")){
		snprintf(pqp->devicename, sizeof(pqp->devicename), "%s", value);
	}else if(!strcmp(feild_name, "deviceservice")){
		snprintf(pqp->deviceservice, sizeof(pqp->deviceservice), "%s", value);
	}else if(!strcmp(feild_name, "deviceticketexpiretime")){
		snprintf(pqp->deviceticketexpiretime, sizeof(pqp->deviceticketexpiretime), "%s", value);
	}else if(!strcmp(feild_name, "time")){
		snprintf(pqp->time, sizeof(pqp->time), "%s", value);
	}else{

	}
	Cdbg(WB_DBG, "end");

	return 0;
}

int 	proc_unregister_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{	
	Cdbg(WB_DBG, "start =========================================================");
	Cdbg(WB_DBG, "name =%s, value=%s", feild_name, value);
	
	UnregisterDevice * pud = (UnregisterDevice*)data_struct;
	if(!strcmp(feild_name, "status") ){
		snprintf(pud->status, sizeof(pud->status), "%s", value);
	}else if(!strcmp(feild_name, "time")){
		snprintf(pud->time, sizeof(pud->time), "%s", value);
	}else{

	}
	Cdbg(WB_DBG, "end <<<<<<<<<<<<<<<<");
	return 0;
}

int 	proc_updateiceinfo_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{	
	Updateiceinfo * pui = (Updateiceinfo*)data_struct;
	
	if(!strcmp(feild_name, "status") ){
		snprintf(pui->status, sizeof(pui->status), "%s", value);
	}else if(!strcmp(feild_name, "time")){
		snprintf(pui->time, sizeof(pui->time), "%s", value);
	}else{
	}
	return 0;
}

int 	proc_keepalive_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{
	Keepalive* pka = (Keepalive*)data_struct;

	if(!strcmp(feild_name, "status") ){
		snprintf(pka->status, sizeof(pka->status), "%s", value);
	}else if(!strcmp(feild_name, "time")){
		snprintf(pka->time, sizeof(pka->time), "%s", value);
	}else if(!strcmp(feild_name, "deviceticketexpiretime")){
		snprintf(pka->deviceticketexpiretime, sizeof(pka->deviceticketexpiretime), "%s", value);
	}else{

	}
	Cdbg(WB_DBG, "end <<<<<<<<<<<<<<<<");

	return 0;
}

int proc_push_msg_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata){
	Push_Msg *pm = (Push_Msg*)data_struct;

	if(!strcmp(feild_name, "status")){
		snprintf(pm->status, sizeof(pm->status), "%s", value);
	}
	else if(!strcmp(feild_name, "time")){
		snprintf(pm->time, sizeof(pm->time), "%s", value);
	}
	else{

	}
	Cdbg(WB_DBG, "end <<<<<<<<<<<<<<<<");

	return 0;
}

int proc_pns_sendmsg_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata){
    PnsSendMsg *psm = (PnsSendMsg*)data_struct;

    if (!strcmp(feild_name, "status")) {
		snprintf(psm->status, sizeof(psm->status), "%s", value);
    } else if (!strcmp(feild_name, "time")) {
		snprintf(psm->time, sizeof(psm->time), "%s", value);
    } else {

    }
    Cdbg(WB_DBG, "end <<<<<<<<<<<<<<<<");

    return 0;
}

int proc_ifttt_notification_json(void* data_struct, struct json_object * json_obj){
    //char *tmp = NULL;
    IftttNotification *ifttt = (IftttNotification*)data_struct;

	if (!data_struct) {
		Cdbg(WB_DBG, "proc_ifttt_notification_json data_struct is NULL.");
		return -1;
	}

	if (!json_obj) {
		Cdbg(WB_DBG, "proc_ifttt_notification_json josn_obj is NULL.");
		return -1;
	}

    Cdbg(WB_DBG, "proc_ifttt_notification_json");
    GET_JSON_STRING_FIELD_TO_ARRARY(json_obj, "status", ifttt->status);
    Cdbg(WB_DBG, "proc_ifttt_notification_json ifttt->status=%s", ifttt->status);
    GET_JSON_STRING_FIELD_TO_ARRARY(json_obj, "message", ifttt->message);
    Cdbg(WB_DBG, "proc_ifttt_notification_json ifttt->message=%s", ifttt->message);
    if (strcmp(ifttt->status, "0")!=0)
        Cdbg(WB_DBG, "error");

    //Cdbg(WB_DBG, "end <<<<<<<<<<<<<<<<");

    return 0;
}

int proc_getuserticketbyrefresh_xml(const char* name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{		
	if(!name || !value || !data_struct) return -1;
	//printf("name <%s> ,value <%s>\n", name, value);
	GetUserTicketByRefresh* pgsa = (GetUserTicketByRefresh*)data_struct;	
	#define TEMP_SIZE 128
	//char 	valuetmp[TEMP_SIZE] ={0};
	//memcpy(valuetmp,"value", value );	

	if(!strcmp(name, "status")) {
		snprintf(pgsa->status, sizeof(pgsa->status), "%s", value);
	}else if(!strcmp(name, "userticket")){
		snprintf(pgsa->userticket, sizeof(pgsa->userticket), "%s", value);
	}else if(!strcmp(name, "userrefreshticket")){
		snprintf(pgsa->userrefreshticket, sizeof(pgsa->userrefreshticket), "%s", value);
	}else if(!strcmp(name, "time")){
		snprintf(pgsa->time, sizeof(pgsa->time), "%s", value);
	}else {
		Cdbg(WB_DBG,"error: unknow tag <%s>, unkonow value <%s>", name, value);
	}
	return 0;
}

int proc_getawscertificate_xml(const char* name, const char* value , void* data_struct, XML_DATA_ * xmldata)
{		
	if(!name || !value || !data_struct) return -1;
	//printf("name <%s> ,value <%s>\n", name, value);
	GetAWSCertificate* pgsa = (GetAWSCertificate*)data_struct;	
	#define TEMP_SIZE 128
	//char 	valuetmp[TEMP_SIZE] ={0};
	//memcpy(valuetmp,"value", value );	

	if(!strcmp(name, "status")) {
		snprintf(pgsa->status, sizeof(pgsa->status), "%s", value);
	}else if(!strcmp(name, "awsiotendpoint")){
		snprintf(pgsa->awsiotendpoint, sizeof(pgsa->awsiotendpoint), "%s", value);
	}else if(!strcmp(name, "rootca")){
		snprintf(pgsa->rootca, sizeof(pgsa->rootca), "%s", value);
	}else if(!strcmp(name, "certificate")){
		snprintf(pgsa->certificate, sizeof(pgsa->certificate), "%s", value);
	}else if(!strcmp(name, "privatekey")){
		snprintf(pgsa->privatekey, sizeof(pgsa->privatekey), "%s", value);
	}else if(!strcmp(name, "message")){
		snprintf(pgsa->message, sizeof(pgsa->message), "%s", value);
	}else {
		Cdbg(WB_DBG,"error: unknow tag <%s>, unkonow value <%s>", name, value);
	}
	return 0;
}

int proc_psr_sendmsg_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata){
    PsrSendMsg *psm = (PsrSendMsg*)data_struct;

    if (!strcmp(feild_name, "status")) {
		snprintf(psm->status, sizeof(psm->status), "%s", value);
    } else if (!strcmp(feild_name, "result_httpcode")) {
		snprintf(psm->result_httpcode, sizeof(psm->result_httpcode), "%s", value);
    } else if (!strcmp(feild_name, "result_content")) {
		snprintf(psm->result_content, sizeof(psm->result_content), "%s", value);
    } else if (!strcmp(feild_name, "time")) {
		snprintf(psm->time, sizeof(psm->time), "%s", value);
    } else {

    }
    Cdbg(WB_DBG, "end <<<<<<<<<<<<<<<<");

    return 0;
}

int proc_pns_sendmsg_fcm_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata){
    PnsSendMsgFcm *psmfcm = (PnsSendMsgFcm*)data_struct;

    if (!strcmp(feild_name, "status")) {
		snprintf(psmfcm->status, sizeof(psmfcm->status), "%s", value);
    } else if (!strcmp(feild_name, "time")) {
		snprintf(psmfcm->time, sizeof(psmfcm->time), "%s", value);
    } else {

    }
    Cdbg(WB_DBG, "end <<<<<<<<<<<<<<<<");

    return 0;
}

int proc_remotelogin_xml(const char* feild_name, const char* value , void* data_struct, XML_DATA_ * xmldata){
    RemoteLogin *prl = (RemoteLogin*)data_struct;

    if (!strcmp(feild_name, "status")) {
		snprintf(prl->status, sizeof(prl->status), "%s", value);
    } else if (!strcmp(feild_name, "time")) {
		snprintf(prl->time, sizeof(prl->time), "%s", value);
    } else {

    }
    Cdbg(WB_DBG, "end <<<<<<<<<<<<<<<<");

    return 0;
}

PROC_XML_DATA get_proc_fn(WS_ID wi)
{	
	if(wi == e_getservicearea)	return proc_getservicearea_xml;
	if(wi == e_login) 			return proc_login_xml;
	if(wi == e_queryfriend)		return proc_queryfriend_xml;
	if(wi == e_listprofile)		return proc_listprofile_xml;
	if(wi == e_updateprofile)	return proc_updateprofile_xml;
	if(wi == e_logout)			return proc_logout_xml;
	if(wi == e_getwebpath)		return proc_getwebpath_xml;
	if(wi == e_createpin)		return proc_createpin_xml;
	if(wi == e_querypin)		return proc_querypin_xml;
	if(wi == e_unregister)		return proc_unregister_xml;
	if(wi == e_updateiceinfo)	return proc_updateiceinfo_xml;
	if(wi == e_keepalive)		return proc_keepalive_xml;
	if(wi == e_pushsendmsg)		return proc_push_msg_xml;
    if(wi == e_pnssendmsg)		return proc_pns_sendmsg_xml;
	if(wi == e_getuserticketbyrefresh)	return proc_getuserticketbyrefresh_xml;
	if(wi == e_getawscertificate)	return proc_getawscertificate_xml;
	if(wi == e_psrsendmsg)	return proc_psr_sendmsg_xml;
	if(wi == e_pnssendmsgfcm)	return proc_pns_sendmsg_fcm_xml;
	if(wi == e_remotelogin)	return proc_remotelogin_xml;
}

PROC_JSON_DATA get_proc_json_fn(WS_ID wi)
{
    if (wi == e_iftttnotification)  return proc_ifttt_notification_json;
}

//extend the function for future utility
size_t get_storage_size(WS_ID wi)
{	
	if(wi ==e_getservicearea)	return sizeof(GetServiceArea);
	if(wi ==e_login) 		return sizeof(Login);
	if(wi ==e_queryfriend)		return sizeof(QueryFriend);
	if(wi ==e_listprofile)		return sizeof(ListProfile);
	if(wi ==e_updateprofile)	return sizeof(UpdateProfile);
	if(wi ==e_logout)		return sizeof(Logout);
	if(wi ==e_getwebpath)		return sizeof(Getwebpath);
	if(wi ==e_createpin)		return sizeof(CreatePin);
	if(wi ==e_querypin)		return sizeof(QueryPin);
	if(wi ==e_unregister)		return sizeof(UnregisterDevice);
	if(wi ==e_updateiceinfo)	return sizeof(updateiceinfo_in);
	if(wi ==e_pnssendmsg)	return sizeof(PnsSendMsg);
	if(wi ==e_getuserticketbyrefresh)	return sizeof(GetUserTicketByRefresh);
	if(wi ==e_getawscertificate)	return sizeof(GetAWSCertificate);
	if(wi ==e_psrsendmsg)	return sizeof(PsrSendMsg);
	if(wi ==e_pnssendmsg)	return sizeof(PnsSendMsgFcm);
	if(wi ==e_remotelogin)	return sizeof(RemoteLogin);
	return 0;
}

//extend the function for future utility
void* get_response_storage(WS_ID wi)
{
	void* storage = NULL;
	if(wi ==e_getservicearea)	storage = (void*)malloc(sizeof(GetServiceArea));
	if(wi ==e_login) 			storage = (void*)malloc(sizeof(Login));
	if(wi ==e_queryfriend)		storage = (void*)malloc(sizeof(QueryFriend));
	if(wi ==e_listprofile)		storage = (void*)malloc(sizeof(ListProfile));
	if(wi ==e_updateprofile)	storage = (void*)malloc(sizeof(UpdateProfile));
	if(wi ==e_logout)			storage = (void*)malloc(sizeof(Logout));
	if(wi ==e_getwebpath)		storage = (void*)malloc(sizeof(Getwebpath));
	if(wi ==e_createpin)		storage = (void*)malloc(sizeof(CreatePin));
	if(wi ==e_querypin)			storage = (void*)malloc(sizeof(QueryPin));
	if(wi ==e_unregister)		storage = (void*)malloc(sizeof(UnregisterDevice));
	if(wi ==e_updateiceinfo)	storage = (void*)malloc(sizeof(Updateiceinfo));
	if(wi ==e_pnssendmsg)		storage = (void*)malloc(sizeof(PnsSendMsg));	
	if(wi ==e_getuserticketbyrefresh)	storage = (void*)malloc(sizeof(GetUserTicketByRefresh));
	if(wi ==e_getawscertificate)	storage = (void*)malloc(sizeof(GetAWSCertificate));
	if(wi ==e_psrsendmsg)		storage = (void*)malloc(sizeof(PsrSendMsg));
	if(wi ==e_pnssendmsgfcm)	storage = (void*)malloc(sizeof(PnsSendMsgFcm));
	if(wi ==e_remotelogin)		storage = (void*)malloc(sizeof(RemoteLogin));

	return storage;
}

int process_xml(char* xml_buff, WS_MANAGER*	wm)
{
	//printf("resp buff  >>>>>>>>>>>>>>>>>>> %s\n", xml_buff);  	
	PROC_XML_DATA proc = NULL;	  	  	
	proc = get_proc_fn(wm->ws_id);
	//wm->ws_storage 			= get_storage(wm->ws_id);
	//wm->ws_storage_size 	= get_storage_size(wm->ws_id);
	Cdbg(WB_DBG, "go parse node");		
	parse_node(xml_buff, wm->ws_storage, wm->ws_storage_size, proc);
	return 0;
}

int process_json(char* json_buff, WS_MANAGER*  wm)
{
    //printf("resp buff  >>>>>>>>>>>>>>>>>>> %s\n", xml_buff);      
    PROC_JSON_DATA proc = NULL;
    struct json_object *json_obj = NULL;
    proc = get_proc_json_fn(wm->ws_id);
    //wm->ws_storage            = get_storage(wm->ws_id);
    //wm->ws_storage_size   = get_storage_size(wm->ws_id);
    Cdbg(WB_DBG, "go parse json node");
    //parse_node(json_buff, wm->ws_storage, wm->ws_storage_size, proc);
    Cdbg(WB_DBG, "process_json, json_buff=[%s]", json_buff);
	if (json_buff) {
		json_obj = json_tokener_parse(json_buff);
	} else {
		json_obj = json_tokener_parse("{}");
	}
	return 0;
}

/* curl	write callback,	write data from curl socket to libxml2 text buffer  */ 
size_t write_cb(char *in, size_t size, size_t nmemb, void* cb_data)
{
	size_t 			r	= size * nmemb;  
	RWCB* rwcb = (RWCB*)cb_data;
	char* buff = (char*)rwcb->write_data;
	if(buff){
		Cdbg(WB_DBG, " new buff data >>>>>>>>>>>>>>>>\n%s\n, r =%d, sizeIn =%d", in, r, strlen(in));
		size_t cb_org_size = strlen(buff);
		size_t total_size = cb_org_size +r+1;
		Cdbg(WB_DBG, "....0, total_size=%d", total_size);
		char* new_cb_data = (char*)malloc(total_size);
		Cdbg(WB_DBG, "....1");
		memset(new_cb_data, 0, total_size);
		Cdbg(WB_DBG, "....2");
		strncpy(new_cb_data, buff, cb_org_size);
		// fix curl bug of tail, extra characters occur in the end
		//void* tmp_addr = new_cb_data+strlen(buff);
		//char* tmp = (char*)tmp_addr;
		//strncpy(tmp, in, r);
		Cdbg(WB_DBG, "....3");
		strncat(new_cb_data, in, r);
		Cdbg(WB_DBG, "....44");
		if(buff) free(buff);
		buff = new_cb_data;
	}else{
		Cdbg(WB_DBG, " write_cb >>>>>>>>>>>>>>>>\n%s\n, r =%d, sizeIn =%d", in, r, strlen(in));
		buff = (char*)malloc(r+1);
		memset(buff, 0, r+1);
		strncpy(buff, in, r);
	}
	rwcb->write_data = buff;
	return(r);
}

static size_t read_callback(void *ptr, size_t size,	size_t nmemb, void *userp)
{
   // ptr must be filled data fully , and sent to curl socket buffer
  struct input_info* pooh = (struct input_info*)userp;

  if(size*nmemb	< 1)
	return 0;

  if(pooh->sizeleft) {
	*(char *)ptr = pooh->readptr[0]; /*	copy one single	byte */	
	pooh->readptr++;				 /*	advance	pointer	*/
	pooh->sizeleft--;				 /*	less data left */
	return 1;						 /*	we return 1	byte at	a time!	*/
  }

  return 0;							 /*	no more	data left to deliver */
}

void get_wm(WS_MANAGER* wsM, WS_ID wsID, void* pSrvType, size_t SrvSize )
{
	memset(wsM, 0 , sizeof(wsM));
    wsM->ws_id                = wsID;
	wsM->ws_storage           = pSrvType;
	wsM->ws_storage_size      = SrvSize;
}

int send_req2(char* url, char* append_data, char *wb_custom_hdr, char** response_data )
{
	int ret = -1;
	if(!url || !append_data) 
		goto SEND_REQ_EXIT;

	// wb_custom header is defined in wb_util.h for "Set-Cookie:ONE_VER=1_0; path=/; sid=appid"
	const char* custom_head[] = {wb_custom_hdr, NULL};

	Cdbg(WB_DBG, "start");
	struct input_info 	inbuf;
	//char* cp_append_data = malloc(strlen(append_data)+1);
	//memset(cp_append_data, 0, strlen(append_data)+1);
	//strcpy(cp_append_data, append_data);
	inbuf.readptr = append_data;
	inbuf.sizeleft= strlen(append_data);

	RWCB rwcb;
	memset(&rwcb, 0, sizeof(rwcb));	
	rwcb.write_cb 	= &write_cb;
	rwcb.read_cb 	= &read_callback;
	rwcb.pInput 	= &inbuf;

	curl_io(url, custom_head, &rwcb);
	ret = rwcb.code;
	if(!rwcb.write_data) {
		Cdbg(WB_DBG, "rwcb.write_data is NULL.");
		goto SEND_REQ_EXIT;	
	}

	//if  rwcb.write_data is allocated in write_cb, it should be freed later
	size_t resp_len = strlen((char*)rwcb.write_data)+1;
	*response_data = (char*)malloc(resp_len);
	memset(*response_data, 0, resp_len);
	strcpy(*response_data, (const char*)rwcb.write_data);
	Cdbg(WB_DBG, "send_req2=*response_data=%s", *response_data);
	if(rwcb.write_data) 
		free(rwcb.write_data);
	//ret =0;
SEND_REQ_EXIT:	
	return ret;
}

int send_req(char* url, char* append_data, char** response_data )
{
	return send_req2(url, append_data, wb_custom_header, response_data);
}

int send_keepalive_req(
	const char*	server,
	const char*	cusid,
	const char*	deviceid,
	const char*	deviceticket,
	Keepalive*	pka
)
{
	char*	url = get_webpath(TRANSFER_TYPE, server, KEEP_ALIVE );
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(keepalive_template, cusid, deviceid, deviceticket, pka);
	Cdbg(WB_DBG, "input data >>>>>>>\n %s", append_data);
	char* xml_outbuf=NULL;
	send_req(url, append_data, &xml_outbuf);
	Cdbg(WB_DBG, "xml_outbuf >>>>>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_keepalive, pka, sizeof(Keepalive));
	process_xml(xml_outbuf, &ws_manager);
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);

	return 0;

}

int send_updateiceinfo_req(
	const char*	server,
	const char*	cusid,
	const char*	deviceid,
	const char*	deviceticket,
	const char*	iceinfo,
	Updateiceinfo*	pui
)
{
	char*	url = get_webpath(TRANSFER_TYPE, server, UPDATE_ICE_INFO);
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(updateiceinfo_template, cusid, deviceid, deviceticket, iceinfo);
	Cdbg(WB_DBG, "input data >>>>>>>\n %s", append_data);
	char* xml_outbuf=NULL;
	send_req(url, append_data, &xml_outbuf);
	Cdbg(WB_DBG, "xml_outbuf >>>>>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_updateiceinfo, pui, sizeof(Updateiceinfo));
	process_xml(xml_outbuf, &ws_manager);
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);

	return 0;
}

int send_unregister_device_req(
	const char* 	server,
	const char* 	cusid,
	const char*	deviceid,
	const char*	deviceticket,
	UnregisterDevice*	pud
)
{
	char*	url = get_webpath(TRANSFER_TYPE, server, UNREGISTER);
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(unregister_template, cusid, deviceid, deviceticket);
	Cdbg(WB_DBG, "input data >>>>>>>\n %s", append_data);
	char* xml_outbuf=NULL;
	send_req(url, append_data, &xml_outbuf);
	Cdbg(WB_DBG, "xml_outbuf >>>>>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_unregister, pud, sizeof(UnregisterDevice));
	process_xml(xml_outbuf, &ws_manager);
	Cdbg(WB_DBG, "process xml done");
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);

	return 0;
}

int send_query_pin_req(
	const char*	server,
	const char*	cusid,
	const char*	deviceticket,
	const char*	pin,
	QueryPin*	pqp
)
{
	char*	url = get_webpath(TRANSFER_TYPE, server, QUERY_PIN);
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(querypin_template, cusid,  deviceticket, pin);
	Cdbg(WB_DBG, "input data >>>>>>>\n %s", append_data);
	char* xml_outbuf=NULL;
	send_req(url, append_data, &xml_outbuf);
	Cdbg(WB_DBG, "xml_outbuf >>>>>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_querypin, pqp, sizeof(QueryPin));
	process_xml(xml_outbuf, &ws_manager);
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
	return 0;
}

int send_create_pin_req(
	const char* 	server,
	const char*	cusid,
	const char*	deviceid,
	const char*	deviceticket,
	Getwebpath*	pgw
)
{
	char*	url = get_webpath(TRANSFER_TYPE, server, CREATE_PIN);
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(createpin_template, cusid, deviceid, deviceticket);
	Cdbg(WB_DBG, "input data >>>>>>>\n %s", append_data);
	char* xml_outbuf=NULL;
	send_req(url, append_data, &xml_outbuf);
	Cdbg(WB_DBG, "xml_outbuf >>>>>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_createpin, pgw, sizeof(CreatePin));
	process_xml(xml_outbuf, &ws_manager);
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
	return 0;

}

int send_logout_req(
	const char* 	server, 
	const char* 	cusid,
	const char* 	deviceid,
	const char* 	deviceticket,
	Logout*		plgo
)
{
	char*	url = get_webpath(TRANSFER_TYPE, server, LOGOUT);
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(logout_template, cusid, deviceid, deviceticket);
	Cdbg(WB_DBG, "input data >>>>>>>\n %s", append_data);
	char* xml_outbuf=NULL;
	send_req(url, append_data, &xml_outbuf);
	Cdbg(WB_DBG, "xml_outbuf >>>>>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_logout, plgo, sizeof(Logout));
	process_xml(xml_outbuf, &ws_manager);
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
	return 0;
}

int send_update_profile_req(
	const char* server,
	const char* cusid,
	const char* deviceid,
	const char* deviceticket,
	const char* devicename,
	const char* deviceservice,
	const char* devicestatus,
	const char* permission,
	const char* devicenat,
	const char* devicedesc,
	pUpdateProfile pup)
{
    char* url = get_webpath(TRANSFER_TYPE, server, UPDATE_PROFILE);
    const char* custom_head[] = {wb_custom_header, NULL};
    char* append_data = get_append_data(updateprofile_template, cusid, deviceid,
                                        deviceticket, devicename, deviceservice, devicestatus, 
                                        permission, devicenat, devicedesc);
    Cdbg(WB_DBG, "input data >>>>>>>\n append_data length=[%d], %s", strlen(append_data), append_data);
    char* xml_outbuf=NULL;
    int status, retry_count = 0;
    do {
        if (retry_count > 0)
            Cdbg(WB_DBG, "Retry %d", retry_count);
        status = send_req(url, append_data, &xml_outbuf);
        Cdbg(WB_DBG, "send_update_profile_req >>>>>>>>>>>>>>>>>>>>>>\n %d", status);
    } while (status != 200 && ++retry_count < DM_RETRY_COUNT);
    if (status == 200) {
        Cdbg(WB_DBG, "xml_outbuf >>>>>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
        WS_MANAGER ws_manager;
        get_wm(&ws_manager, e_updateprofile, pup, sizeof(UpdateProfile));
        process_xml(xml_outbuf, &ws_manager);
    }
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
    //return status;
}

int send_list_profile_req(
	const char* 	server,
	const char*	cusid,
	const char*	userticket,
	const char*	deviceticket,
	const char*	friendid,
	const char*	deviceid,
	pListProfile	p_ListProfile) //out
{
	char*	url = get_webpath(TRANSFER_TYPE, server, LIST_PROFILE);
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(listprofile_template, cusid, 
		userticket, deviceticket, friendid, deviceid);
	char* xml_outbuf=NULL;
	send_req(url, append_data, &xml_outbuf);
	Cdbg(WB_DBG, "xml_outbuf >>>>>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_listprofile, p_ListProfile, sizeof(ListProfile));
	process_xml(xml_outbuf, &ws_manager);
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
	return 0;
}

int send_query_friend_req(
	const char* server,
	const char* user_ticket,
	QueryFriend*	fd_list
	)
{
	Cdbg(WB_DBG, "Start Send fd_list=%p", fd_list);
	char* url = get_webpath(TRANSFER_TYPE, server, QUERY_FRIEND);
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(queryfriend_template, user_ticket);
	char* xml_outbuf=NULL;
	send_req(url, append_data, &xml_outbuf);
//	send_req(url, append_data,fd_list, sizeof(QueryFriend), e_queryfriend);
	Cdbg(WB_DBG, "Start Send Done, >>>>> Return data >>>>>\n%s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_queryfriend, fd_list, sizeof(QueryFriend));
	process_xml(xml_outbuf, &ws_manager);
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
	Cdbg(WB_DBG,">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>============= fd_list->FriendList=%p", fd_list->FriendList);
	return 0;
}

int send_loginbyticket_req(
	const char* server,
//	const char* userid, 
//	const char* passwd,
	const char* userticket,
	const char* devicemd5mac,
	const char*	devicename,
	const char*	deviceservice,
	const char* devicetype,
	const char*	permission,
	const char* devicedesc,
	Login*		pLogin
)
{	
	char* url = get_webpath(TRANSFER_TYPE, server, LOGIN);
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(loginbyticket_template, 
					userticket, devicemd5mac, devicename,
				deviceservice, devicetype, permission, devicedesc);
	Cdbg(WB_DBG, "append_data >>>>>>>>>>>>>>\n %s", append_data);
	char* xml_outbuf=NULL;
	send_req(url, append_data, &xml_outbuf);
	Cdbg(WB_DBG, "xml out buffer >>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_login, pLogin, sizeof(Login));
	process_xml(xml_outbuf, &ws_manager);
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
	return 0;
}


int send_login_req(
	const char* server,
	const char* userid, 
	const char* passwd,
	const char* cusid, 
	const char* userticket,
	const char* devicemd5mac,
	const char*	devicename,
	const char*	deviceservice,
	const char* devicetype,
	const char*	permission,
	const char* devicedesc,
	const char* fwver, 
	const int apilevel,
	const char* modelname,
	Login*		pLogin
)
{	
    sprintf(wb_custom_header, wb_custom_header_templ, deviceservice, devicetype, fwver, DM_API_LEVEL, apilevel, modelname);

	char* url = get_webpath(TRANSFER_TYPE, server, LOGIN);
	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(login_template, 
					userid, passwd, cusid, userticket, devicemd5mac, devicename,
				deviceservice, devicetype, permission, devicedesc);
	int status;
	Cdbg(WB_DBG, "append_data >>>>>>>>>>>>>>\n %s", append_data);
	char* xml_outbuf=NULL;
	status = send_req(url, append_data, &xml_outbuf);
	Cdbg(WB_DBG, "xml out buffer >>>>>>>>>>>>>>>>>>>\n %s", xml_outbuf);
	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_login, pLogin, sizeof(Login));
//	Cdbg(WB_DBG, "<<<<<<<<<<<<<<<<<<<<<<<<<<<<< server=%s", server);
	process_xml(xml_outbuf, &ws_manager);
    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
}

int send_getservicearea_req(
	const char* server, 
	const char* serviceid, 
	const char* userid, 
	const char* passwd,
	const char* devicetype, 
	const char* fwver, 
	const int apilevel,
	const char* modelname,
	GetServiceArea* pGSA//out put
	)
{	
	// get url by allocate
	char* url	= get_webpath(TRANSFER_TYPE, server,GET_SERVICE_AREA ); 
	int status;

    sprintf(wb_custom_header, wb_custom_header_templ, serviceid, devicetype, fwver, DM_API_LEVEL, apilevel, modelname);

	const char* custom_head[] = {wb_custom_header, NULL};	
	char* append_data	= get_append_data(getservicearea_template, userid, passwd);
	char* xml_outbuf =NULL;
	Cdbg(WB_DBG, "ws manager setting 1, xml_outbuf=%p", xml_outbuf);
	
	status = send_req(url, append_data, &xml_outbuf);

	Cdbg(WB_DBG, "ws manager setting");
	WS_MANAGER	ws_manager;
	get_wm(&ws_manager, e_getservicearea, pGSA, sizeof(GetServiceArea));
	Cdbg(WB_DBG, "ws manager setting done");
	Cdbg(WB_DBG, "start proc xml");
	process_xml(xml_outbuf, &ws_manager);
	Cdbg(WB_DBG, "end proc xml outbuf >>>>>>>>>>>>\n %s", xml_outbuf);

    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
}

int send_push_msg_req(
	const char *server,
	const char *mac,
	const char *token,
	const char *msg,
	Push_Msg *pPm
	)
{
	char *url	= get_webpath(TRANSFER_TYPE, server, PUSH_SENDMSG);
	char *append_data	= get_append_data(push_msg_template, mac, token, msg);
	char *xml_outbuf = NULL;
	int status;

	Cdbg(WB_DBG, "send_push_msg_req: send append_data:\n%s.\n", append_data);
	status = send_req(url, append_data, &xml_outbuf);

	Cdbg(WB_DBG, "send_push_msg_req: ws manager setting.\n");
	WS_MANAGER	ws_manager;
	get_wm(&ws_manager, e_getservicearea, pPm, sizeof(Push_Msg));
	Cdbg(WB_DBG, "send_push_msg_req: done. status=%d\n", status);
	Cdbg(WB_DBG, "send_push_msg_req: start proc xml.\n");
	process_xml(xml_outbuf, &ws_manager);
	Cdbg(WB_DBG, "end proc xml outbuf >>>>>>>>>>>>\n%s", xml_outbuf);

    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
}

int send_pns_sendmsg_req(
                     const char *server,
                     const char *cusid,
                     const char *deviceid,
                     const char *deviceticket,
                     const char *appids,
                     const char *todeviceid,
					 const char* devicetype, 
					 const char* fwver, 
					 const char* apilevel,
					 const char* modelname,
                     const char *msg,
                     PnsSendMsg *pPsm
                     )
{
    char *url   = get_webpath(TRANSFER_TYPE, server, PNS_SENDMSG);
    char *append_data = get_append_data(pns_sendmsg_template, cusid, 
                                        deviceid, deviceticket, todeviceid, msg);
    char *xml_outbuf = NULL;
    char custom_head[256];
    int status;

    Cdbg(WB_DBG, "send_pns_sendmsg_req: send append_data:\n%s.\n", append_data);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("send append_data:\n%s.\n", append_data);
#endif

    snprintf(custom_head, sizeof(custom_head), wb_custom_header_templ2, appids, devicetype, fwver, DM_API_LEVEL, apilevel, modelname);
    status = send_req2(url, append_data, custom_head, &xml_outbuf);

    Cdbg(WB_DBG, "send_pns_sendmsg_req: ws manager setting.\n");
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("ws manager setting.\n");
#endif
    WS_MANAGER  ws_manager;
    get_wm(&ws_manager, e_pnssendmsg, pPsm, sizeof(PnsSendMsg));
    Cdbg(WB_DBG, "send_pns_sendmsg_req: done. status=%d\n", status);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("done. status=%d\n", status);
#endif
    Cdbg(WB_DBG, "send_pns_sendmsg_req: start proc xml.\n");
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("start proc xml.\n");
#endif
    process_xml(xml_outbuf, &ws_manager);
    Cdbg(WB_DBG, "end proc xml outbuf >>>>>>>>>>>>\n%s", xml_outbuf);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("end proc xml outbuf >>>>>>>>>>>>\n%s\n", xml_outbuf);
#endif

    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
}

int send_ifttt_notification_req(
	const char *server,
	const char *trigger,
	const char *msg,
	IftttNotification *pIftttnotification
	)
{
#define RES_401_UNAUTHORIZED 401
#define RES_406_NOT_ACCEPTABLE 406
    char *url = get_webpath(TRANSFER_TYPE, server, trigger);
    char *append_data = get_append_data(ifttt_notification_template, msg);
    char *json_outbuf = NULL;
    char *custom_head = (char *)ifttt_notification_header_templ;

    Cdbg(WB_DBG, "url=[%s], send append_data:[%s]", url, append_data);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
       IFTTT_DEBUG("url=[%s], send append_data:[%s]", url, append_data);
#endif

    //sprintf(custom_head, ifttt_notification_header_templ);
    int status, retry_count = 0;
    do {
        if (retry_count > 0) {
            Cdbg(WB_DBG, "Retry %d", retry_count);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
       		IFTTT_DEBUG("Retry %d\n", retry_count);
#endif
        }
        status = send_req2(url, append_data, custom_head, &json_outbuf);
    } while (status != 200 && status != RES_401_UNAUTHORIZED && status != RES_406_NOT_ACCEPTABLE && ++retry_count < DM_RETRY_COUNT);

    if (status == 200 || status == RES_401_UNAUTHORIZED || status == RES_406_NOT_ACCEPTABLE) {
        //Cdbg(WB_DBG, "send_ifttt_notification_req: ws manager setting.");
        WS_MANAGER  ws_manager;
        get_wm(&ws_manager, e_iftttnotification, pIftttnotification, sizeof(IftttNotification));
        //Cdbg(WB_DBG, "send_ifttt_notification_req: done. status=%d", status);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
        IFTTT_DEBUG("done. status=%d\n", status);
#endif
        //Cdbg(WB_DBG, "send_ifttt_notification_req: start proc json.");
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
       	IFTTT_DEBUG("start proc json.\n");
#endif
        process_json(json_outbuf, &ws_manager);
        //Cdbg(WB_DBG, "end proc json outbuf >>>>>>>>>>>>\n%s", json_outbuf);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
       	IFTTT_DEBUG("end proc json outbuf >>>>>>>>>>>>\n%s\n", json_outbuf);
#endif
    }

    if (append_data) free_append_data(append_data);
    if (json_outbuf) free(json_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
    //return status;
}

int send_getuserticketbyrefresh_req(
	const char* server, 
	const char* serviceid, 
	const char* cusid, 
	const char* devicemd5mac,
	const char* refresh_ticket,
	const char* devicetype, 
	const char* fwver, 
	const int apilevel,
	const char* modelname,
	GetUserTicketByRefresh* pGetUserTicketByRefresh//out put
	)
{	
	// get url by allocate
	char* url	= get_webpath(TRANSFER_TYPE, server, GET_USER_TICKET_BY_REFRESH); 
	int status;
	
    sprintf(wb_custom_header, wb_custom_header_templ, serviceid, devicetype, fwver, DM_API_LEVEL, apilevel, modelname);

	const char* custom_head[] = {wb_custom_header, NULL};	
	char* append_data	= get_append_data(getuserticketbyrefresh_template, cusid, devicemd5mac, refresh_ticket);
	char* xml_outbuf =NULL;
	
	status = send_req(url, append_data, &xml_outbuf);

	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_getuserticketbyrefresh, pGetUserTicketByRefresh, sizeof(GetUserTicketByRefresh));
	process_xml(xml_outbuf, &ws_manager);

	// Cdbg(WB_DBG, "end proc xml outbuf >>>>>>>>>>>>\n %s", xml_outbuf);

    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
}

int send_getawscertificate_req(
	const char* server, 
	const char* serviceid, 
	const char* cusid, 
	const char* userticket,
	const char* deviceid,
	const char* deviceticket,
	const char* devicetype, 
	const char* fwver, 
	const int apilevel,
	const char* modelname,
	GetAWSCertificate* pGetAWSCertificate//out put
	)
{	
	// get url by allocate
	char* url	= get_webpath(TRANSFER_TYPE, server, GET_AWS_CERTIFICATE); 
	int status;
	
    sprintf(wb_custom_header, wb_custom_header_templ, serviceid, devicetype, fwver, DM_API_LEVEL, apilevel, modelname);

	const char* custom_head[] = {wb_custom_header, NULL};	
	char* append_data	= get_append_data(getawscertificate_template, cusid, userticket, deviceid, deviceticket);
	char* xml_outbuf =NULL;
	
	status = send_req(url, append_data, &xml_outbuf);

	WS_MANAGER ws_manager;
	get_wm(&ws_manager, e_getawscertificate, pGetAWSCertificate, sizeof(GetAWSCertificate));
	process_xml(xml_outbuf, &ws_manager);

	// Cdbg(WB_DBG, "end proc xml outbuf >>>>>>>>>>>>\n %s", xml_outbuf);

    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
}

int send_psr_sendmsg_req(
                     const char *server,
                     const char *cusid,
                     const char *deviceid,
                     const char *deviceticket,
                     const char *appids,
                     const char* devicetype, 
					 const char* fwver, 
					 const char* apilevel,
					 const char* modelname,
                     const char *payload,
                     PsrSendMsg *pPsm
                     )
{
    char *url   = get_webpath(TRANSFER_TYPE, server, PSR_SENDMSG);
    char *append_data = get_append_data(psr_sendmsg_template, cusid, 
                                        deviceid, deviceticket, payload);
    char *xml_outbuf = NULL;
    char custom_head[256];
    int status;

    Cdbg(WB_DBG, "send_psr_sendmsg_req: send append_data:\n%s.\n", append_data);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("send append_data:\n%s.\n", append_data);
#endif

    snprintf(custom_head, sizeof(custom_head), wb_custom_header_templ2, appids, devicetype, fwver, DM_API_LEVEL, apilevel, modelname);
    status = send_req2(url, append_data, custom_head, &xml_outbuf);

    Cdbg(WB_DBG, "send_psr_sendmsg_req: ws manager setting.\n");
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("ws manager setting.\n");
#endif
    WS_MANAGER  ws_manager;
    get_wm(&ws_manager, e_psrsendmsg, pPsm, sizeof(PsrSendMsg));
    Cdbg(WB_DBG, "send_psr_sendmsg_req: done. status=%d\n", status);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("done. status=%d\n", status);
#endif
    Cdbg(WB_DBG, "send_psr_sendmsg_req: start proc xml.\n");
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("start proc xml.\n");
#endif
    process_xml(xml_outbuf, &ws_manager);
    Cdbg(WB_DBG, "end proc xml outbuf >>>>>>>>>>>>\n%s", xml_outbuf);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("end proc xml outbuf >>>>>>>>>>>>\n%s\n", xml_outbuf);
#endif

    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
}

int send_pns_sendmsg_fcm_req(
                     const char *server,
                     const char *cusid,
                     const char *deviceid,
                     const char *deviceticket,
                     const char *appids,
					 const char* devicetype, 
					 const char* fwver, 
					 const char* apilevel,
					 const char* modelname,
                     const char *msg,
                     PnsSendMsgFcm *pPsm
                     )
{
    char *url   = get_webpath(TRANSFER_TYPE, server, PNS_SENDMSG_FCM);
    char *append_data = get_append_data(pns_sendmsg_fcm_template, cusid, 
                                        deviceid, deviceticket, msg);
    char *xml_outbuf = NULL;
    char custom_head[256];
    int status;
    fprintf(stderr, "%s\n", append_data);

    Cdbg(WB_DBG, "send_pns_sendmsg_fcm_req: send append_data:\n%s.\n", append_data);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("send append_data:\n%s.\n", append_data);
#endif

    snprintf(custom_head, sizeof(custom_head), wb_custom_header_templ2, appids, devicetype, fwver, DM_API_LEVEL, apilevel, modelname);
    status = send_req2(url, append_data, custom_head, &xml_outbuf);

    Cdbg(WB_DBG, "send_pns_sendmsg_fcm_req: ws manager setting.\n");
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("ws manager setting.\n");
#endif
    WS_MANAGER  ws_manager;
    get_wm(&ws_manager, e_pnssendmsgfcm, pPsm, sizeof(PnsSendMsgFcm));
    Cdbg(WB_DBG, "send_pns_sendmsg_fcm_req: done. status=%d\n", status);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("done. status=%d\n", status);
#endif
    Cdbg(WB_DBG, "send_pns_sendmsg_fcm_req: start proc xml.\n");
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("start proc xml.\n");
#endif
    process_xml(xml_outbuf, &ws_manager);
    Cdbg(WB_DBG, "end proc xml outbuf >>>>>>>>>>>>\n%s", xml_outbuf);
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("end proc xml outbuf >>>>>>>>>>>>\n%s\n", xml_outbuf);
#endif

    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
}

int send_remotelogin_req(
					const char *server,
					const char* serviceid, 
					const char *oauth_dm_cusid,
					const char *mobile_deviceid,
					const char *dm_ticket,
					const char* devicetype, 
					const char* fwver, 
					const int apilevel,
					const char* modelname,
					RemoteLogin *pRl
					)
{
	// get url by allocate
	char* url	= get_webpath(TRANSFER_TYPE, server, REMOTELOGIN); 
	int status;

	sprintf(wb_custom_header, wb_custom_header_templ, serviceid, devicetype, fwver, DM_API_LEVEL, apilevel, modelname);

	const char* custom_head[] = {wb_custom_header, NULL};
	char* append_data	= get_append_data(remotelogin_template, oauth_dm_cusid, mobile_deviceid, dm_ticket);

	Cdbg(WB_DBG, "send append_data:\n%s.\n", append_data);
	char* xml_outbuf =NULL;
	Cdbg(WB_DBG, "ws manager setting 1, xml_outbuf=%p", xml_outbuf);

	status = send_req(url, append_data, &xml_outbuf);

	Cdbg(WB_DBG, "ws manager setting");
	WS_MANAGER	ws_manager;
	get_wm(&ws_manager, e_remotelogin, pRl, sizeof(RemoteLogin));
	Cdbg(WB_DBG, "ws manager setting done");
	Cdbg(WB_DBG, "start proc xml");
	process_xml(xml_outbuf, &ws_manager);
	Cdbg(WB_DBG, "end proc xml outbuf >>>>>>>>>>>>\n %s", xml_outbuf);

    if (append_data) free_append_data(append_data);
    if (xml_outbuf) free(xml_outbuf);
	if (url) free_webpath(url);
    return status == 200 ? 0 : status;
}
