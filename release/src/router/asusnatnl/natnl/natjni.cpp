/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <string.h>
#include <jni.h>
#include <natnl_lib.h>
#include <stdio.h>
#include <errno.h>
#include <version.h>
#include <stdlib.h>
//#include <version.h>

#define VER_2_1_0_114 1

#define THIS_FILE "NAT_DUMP" 
#if PJ_ANDROID ==1
#include <j_log.h>
#include <sys/ioctl.h>
#else
#define LOG_E(x, ...)
#endif

#define MAX_SRV_PORTS	8 
#define MAX_FILE_LEN	256
#define MAX_ID_LEN		128
#define MAX_URI_LEN		128
#define IsNULL_PTR(x) (!x)?1:0


//static const char *javaClassPath = "com/asus/natjni/NatAPI";
//static const char *javaClassPath = "com/asus/natapi/NatAPI";
//static const char *javaClassPath = "com/asus/nat/NatJni";
static const char*  javaClassPath = "com/asus/natapi/NatNativeAPI";
static const char*  javaLogClsPath  = "com/asus/natapi/NatNativeAPI";
static const char*  javaTnlPortsClsPath  = "com/asus/natapi/NatTnlPort";
static const char*  javaImPortsClsPath  = "com/asus/natapi/NatImPort";

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define JAVA_LIB_CLASS_PATH "Lcom/asus/natapi/"
#define JNATAPI_CLASS       NatNativeAPI;
#define JLOGCFG_CLASS       LogCfg;
#define JNATCB_CLASS        NatcALLBACK;
#define JNATCFG_CLASS       NatConfig;
#define JNATTNLPORT_CLASS      NatTnlPort;
#define JUPNPCFG_CLASS      UpnpCfg;
#define JUSERPORT_CLASS     UserPort;
#define JIMPORT_CLASS     NatImPort;
#define CALLINFO_CLASS	    CallInfo;
#define JPARAINFO_CLASS		ParaInfo;	// +Roger
#define JREMOTE_CLASS		RemoteInfo;	// +Roger
#define JLOCAL_CLASS		LocalInfo;	// +Roger
#define JRETRYCNT_CLASS		NatRetryCount;	// +Dean
#define JNATIVE_CLASS_PATH      JAVA_LIB_CLASS_PATH TOSTRING(JNATAPI_CLASS)
#define JLOGCFG_CLASS_PATH      JAVA_LIB_CLASS_PATH TOSTRING(JLOGCFG_CLASS)
#define JNATCB_CLASS_PATH       JAVA_LIB_CLASS_PATH TOSTRING(JNATCB_CLASS)
#define JNATCFG_CLASS_PATH      JAVA_LIB_CLASS_PATH TOSTRING(JNATCFG_CLASS)
#define JNATTNLPORT_CLASSS_PATH    JAVA_LIB_CLASS_PATH TOSTRING(JNATTNLPORT_CLASS)
#define JUPNPCFG_CLASS_PATH     JAVA_LIB_CLASS_PATH TOSTRING(JUPNPCFG_CLASS)
#define JUSERPORT_CLASS_PATH    JAVA_LIB_CLASS_PATH TOSTRING(JUSERPORT_CLASS)
#define JIMPORT_CLASS_PATH    JAVA_LIB_CLASS_PATH TOSTRING(JIMPORT_CLASS)
#define CALLINFO_CLASS_PATH		JAVA_LIB_CLASS_PATH TOSTRING(CALLINFO_CLASS)
#define JPARAINFO_CLASS_PATH	JAVA_LIB_CLASS_PATH	TOSTRING(JPARAINFO_CLASS)	//+Roger
#define JREMOTE_CLASS_PATH		JAVA_LIB_CLASS_PATH	TOSTRING(JREMOTE_CLASS)		//+Roger
#define JLOCAL_CLASS_PATH		JAVA_LIB_CLASS_PATH	TOSTRING(JLOCAL_CLASS)		//+Roger
#define JRETRYCNT_CLASS_PATH		JAVA_LIB_CLASS_PATH	TOSTRING(JRETRYCNT_CLASS)		//+Dean

typedef struct _JNIDATA
{
	JavaVM *vm;
	jobject interfaceObject;    
//    JNIEnv *env;
} JNIDATA, *P_JNIDATA;
static JNIDATA jniData;

typedef struct _JNAT_DATA
{
    jobject     obj_callback;
    jclass      cls_callback;
    jmethodID   md_callback;
} JNATDATA, *PNATDATA;
static  JNATDATA jNatData;
//Global declare, the array of service port pair.
static natnl_tnl_port natnl_tnl_ports[MAX_TUNNEL_PORT_COUNT];

//Global declare, the number of service ports.
static int natnl_tnl_port_count; 
struct	natnl_config	natnl_config;
//charles
//char						registrar_uri[MAX_URI_LEN];
//charles
//int						g_call_id;

#define     VAR_LEN 128
char        gcb_member_name[VAR_LEN];
char        gcb_class_name[VAR_LEN]; 
char        gcb_class_path[VAR_LEN]; 

//---------------------------utility---------------------------------
// Globals
static jmethodID midStr;
jclass gcls;
jobject  gJniObj;
jmethodID construction_id;

int 
JCallNatCB(jobject obj_natcb, struct natnl_tnl_event *tnl_event);


jint JGetCharStringElement(JNIEnv *env, jobjectArray in_objarray, char* out_char, int index )
{
	jstring tmp_str			= (jstring)		env->GetObjectArrayElement( in_objarray, index);
	const char* tmp_chr		= (const char*)	env->GetStringUTFChars(tmp_str, 0);
	strcpy(out_char, tmp_chr);
	if (!IsNULL_PTR(tmp_chr))	env->ReleaseStringUTFChars (tmp_str, tmp_chr);
//	if (!IsNULL_PTR(tmp_str))	env->ReleaseObjectArrayElement(in_objarray, tmp_str, index);
	return 0;
//	env->DeleteLocalRef(env, objarray);
}

jsize get_jstr_len(JNIEnv *env, jstring jstr)
{
	jclass clsstring = env->FindClass("java/lang/String");
	jstring strencode = env->NewStringUTF("utf-8");
	jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
	jbyteArray bytes = (jbyteArray)env->CallObjectMethod(jstr, mid, strencode);
	jsize len = env->GetArrayLength(bytes);
	return len;
}

static inline char* JStringToChar(
	JNIEnv *env,
	jstring jstr, 
	char *to_buf, 
	int buf_size)
{
	if(!jstr || !to_buf || !buf_size) return NULL;
	char *P = to_buf;

	if (IsNULL_PTR(to_buf) && buf_size <= 0)
	{
		return NULL;
	}

	jclass clsstring = env->FindClass("java/lang/String");
	jstring strencode = env->NewStringUTF("utf-8");
	jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
	jbyteArray bytes = (jbyteArray)env->CallObjectMethod(jstr, mid, strencode);
	jsize alen = env->GetArrayLength(bytes);
	jbyte* ba = env->GetByteArrayElements(bytes, JNI_FALSE);
	if (alen > 0)
	{
		memcpy(P, ba, (buf_size<alen)?buf_size:alen);
	}
	env->ReleaseByteArrayElements(bytes, ba, 0);
	return P;
}

/*
// Methods
JNIEXPORT void JNICALL
get_java_natnlcb_methodid(JNIEnv *env,jobject thiz, char* cbname) {
    // Init - One time to initialize the method id, (use an init() function)    
    char * sigStr = "(I)V";
    LOG_E(THIS_FILE, "........1 get class obj");
    gcls = env->FindClass(javaClassPath);
    //jclass cls = env->GetObjectClass(thiz);     
    if(!gcls) return ;    
    LOG_E(THIS_FILE, "........2 gcls = %d", gcls);
    char callbackname[32];
    //char* cbname = "NatCb\0";
    memset(callbackname, 0, sizeof(callbackname));
    strcpy(callbackname, cbname);
    midStr = env->GetMethodID(gcls, callbackname, sigStr);        
    if(!midStr) return ;    

    //construction_id = env->GetMethodID( cls, "<init>", "()V"); 
    //gJniObj = env->NewObject(cls, construction_id);
     
    LOG_E(THIS_FILE, "........3 midstr=%d, ", midStr);
}
*/

static inline long GetJStrLen(
							  JNIEnv *env,
							  jstring jstr)
{
	if(!jstr) return 0;

	jclass clsstring = env->FindClass("java/lang/String");
	jstring strencode = env->NewStringUTF("utf-8");
	jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
	jbyteArray bytes = (jbyteArray)env->CallObjectMethod(jstr, mid, strencode);
	jsize alen = env->GetArrayLength(bytes);
	return alen;
}

static void java_callback(JNIEnv * env, jobject o, int a)
{
    //jobject obj = env->NewObject(cls,midStr);    
    LOG_E(THIS_FILE, "........4");
    env->CallVoidMethod(o, midStr, a);
}
#if 1
int get_feild_class_ptr(
    JNIEnv* env,
    jobject parent_obj, 
    char*   field_name, //  mNatCb
    char*   cls_name,   //  NatCb
    char*   target_class_path,
    jclass* tar_cls,     //  returned class
    jobject* tar_obj
    )//"Lcom/asus/natjni/NatJni/NatCb;"
{
    jclass      parent_cls;
    jfieldID    fieldid;
    jobject     member_obj;
    int         err = -1;

    if(parent_obj   == NULL ||
       field_name   == NULL ||
       cls_name     == NULL || 
       target_class_path == NULL) {
        LOG_E(THIS_FILE, "get_field_class_ptr : ERROR: Invalid parameters ");
        goto get_field_class_ptr_EXIT;
    }
    
    LOG_E(THIS_FILE, "target_class_path =%s,field_name=%s ", target_class_path,field_name);
    // get class pointer from class object
    parent_cls = env->GetObjectClass(parent_obj);
    LOG_E(THIS_FILE, "parent_cls =%d", parent_cls);
    if(!parent_cls) goto get_field_class_ptr_EXIT;
    // get field member id from class 
    fieldid = env->GetFieldID(parent_cls, field_name, target_class_path);
    LOG_E(THIS_FILE, "fieldid =%d", fieldid);   
    if(!fieldid) goto get_field_class_ptr_EXIT;
    // 
    member_obj = env->GetObjectField( parent_obj, fieldid);
    *tar_obj = member_obj;
    LOG_E(THIS_FILE, "member obj =%d ", member_obj);
    if(!member_obj) goto get_field_class_ptr_EXIT;
    //if(!natcb_obj) goto NatSetCb_Exit;
    *tar_cls = env->GetObjectClass( member_obj);
    LOG_E(THIS_FILE, "tar_cls =%d ", *tar_cls);
    if(!*tar_cls) goto get_field_class_ptr_EXIT;
    err = 0;
get_field_class_ptr_EXIT:
    LOG_E(THIS_FILE, "get_field_class_ptr ends");
    return err;
}

int get_methodid( JNIEnv*    env,
                         jclass     tar_cls, 
                         const char*      func_name, 
                         const char*      func_sign, 
                         jmethodID*  methodid)
{
//    jmethodID   methodid=0;
    //methodid = env->GetMethodID(natcb_cls, "on_natnl_tnl_event", "()V"); 
    *methodid = env->GetMethodID(tar_cls, func_name, func_sign);
    if(!*methodid) return -1;
    return 0;
}

int get_fieldid(JNIEnv*   env,
                  jclass    tar_cls,
                  const char*     field_name,
                  const char*     field_sign, // int, void, String , etc...
                  jfieldID* fieldid
                  )
{   
    *fieldid = env->GetFieldID(tar_cls, field_name, field_sign);
    if(!*fieldid) return -1;
    return 0;
}

int set_INT_fieldid_value(JNIEnv*   env, jobject obj, jfieldID fid, int value)
{
    env->SetIntField(obj, fid, value);
    return 0;
}

int get_INT_field(JNIEnv*   env, jobject obj, jfieldID fid)
{
     env->GetIntField(obj, fid);
     return 0;
}

int get_INT_value(JNIEnv*   env, 
                          jclass    tar_cls, 
                          jobject   obj, 
                          const char*     field_name, 
                          int*      value)
{
	if(!field_name) return -1;
	jfieldID    fieldid;
	
	get_fieldid(env, tar_cls, field_name, "I", &fieldid);
	//    LOG_E(THIS_FILE, "get %d = [%d]",field_name, *value);
	*value = env->GetIntField(obj, fieldid);    
	return 0;
}

int
get_Obj( JNIEnv*  env, 
         jclass   cls, 
         jobject  parent_obj,
         const char*    class_path,
         const char*    name, 
         jobject*    obj )
{
    //jstring string_fd;

    jfieldID fid = env->GetFieldID(cls, name, class_path);
//    LOG_E(THIS_FILE, "class path =%s, name=%s", class_path, name);
    *obj = env->GetObjectField(parent_obj, fid);
    if(*obj) return 0;
    else        return -1;
}

int
get_Array_Obj( JNIEnv*  env, 
               jclass   cls, 
               jobject  parent_obj,
               const char*    class_path,
               const char*    Arrayfieldname, 
               jobjectArray*    arr_obj )
{
    /*
    jfieldID fieldid;
    get_fieldid(env, cls, Arrayfieldname, class_path, &fieldid);
    LOG_E(THIS_FILE, "fieldid =%d", fieldid);                   
    arr_obj =  (jobjectArray)env->GetObjectField( obj_natcfg, fieldid); 
    */ 
    return get_Obj(env, cls,parent_obj, class_path, Arrayfieldname, (jobject*)arr_obj);
}

int set_IntArray_value(JNIEnv *env,
	  jclass cls,
	  jobject obj,
	  const char* name,
	  int int_array[],
	  int array_size)
{
	
    LOG_E(THIS_FILE, "set IntArray  1");
	jfieldID fid = env->GetFieldID(cls, name, "[I");
    LOG_E(THIS_FILE, "set IntArray  fid =%d", fid);
	jintArray field_var = (jintArray) env->GetObjectField(obj,fid);
    LOG_E(THIS_FILE, "set IntArray  array size =%d", array_size);
	//for(int i = 0; i<array_size; i++){
	//for(int i = 0; i<4; i++){
	//	LOG_E(THIS_FILE, "array[%d]=%d", i, int_array[i]);
	//}
	
	env->SetIntArrayRegion(field_var, 0, array_size, (const jint*)int_array );	
	return 0;
}

int set_String_value(JNIEnv *env,
                           jclass cls,
                           jobject obj,
                           const char *name,
                           const char *val)
{
    jfieldID fid = env->GetFieldID(cls, name, "Ljava/lang/String;");
    LOG_E(THIS_FILE, "name =%s, value = %s", name, val);
	if(name && val)
		env->SetObjectField(obj, fid,  val ? env->NewStringUTF(val) : NULL);
    return 0;
}

int get_String_value_j(JNIEnv *env,
                           jclass cls,
                           jobject obj,
                           const char *name,
                           jstring* string_fd)
{
    jfieldID fid = env->GetFieldID(cls, name, "Ljava/lang/String;");    
    *string_fd = (jstring)env->GetObjectField(obj, fid);
    return 0;
}

int get_String_value_c(JNIEnv *env,
                           jclass cls,
                           jobject obj,
                           const char *name,
                           char* string_value,
                           size_t string_len) //output
{
    /*
    jstring string_fd;
    jfieldID fid = env->GetFieldID(cls, name, "Ljava/lang/String;");    
    string_fd = (jstring)env->GetObjectField(obj, fid);
    JStringToChar(env, string_fd, string_value, string_len); 
    */
	if(!cls || !obj ||!name ||!string_value) return -1;
    jstring string_obj;
    get_Obj(env,cls,obj,"Ljava/lang/String;", name,(jobject*)&string_obj ) ;
	if(!string_obj) return -1;
    JStringToChar(env, string_obj, string_value, string_len); 
    return 0;
}

/*
int set_JSTRING_fieldid_value(JNIEnv*   env, jobject obj, jfieldID fid, const char* value)
{
    env->SetStringField(env, obj, fid, value);
} 
*/ 
#endif


int Call_java_void_method(
    JNIEnv* env, 
    jclass  cls, 
    jobject obj, 
    const char*   func_name, 
    const char*   func_sign)
{    
    LOG_E(THIS_FILE, "=============================> Call_java_void_method() ");
    int         err = -1;
    jmethodID   methodid;
    LOG_E(THIS_FILE, "=============================> get_methodid, cls =%d, obj=%d ", cls, obj);
    err = get_methodid(env, cls, func_name, func_sign, &methodid);
    LOG_E(THIS_FILE, "=============================> CallVoidMethod ");
    env->CallVoidMethod(obj, methodid);
    return  err;
}

//---------------------------utility---------------------------------


//--------------------------------------------------------------------------------------------
jobject gNatcb_obj;
jclass  gNatcb_cls;

int Set_natcb_INT_value(
    JNIEnv* env, 
    jobject obj,
    jclass  cb_cls,
    const char*   field_name,
    int     value
                        )
{
    jfieldID fid;
    //LOG_E(THIS_FILE, "Set_natcb_INT_value: call getid ");        
    get_fieldid(env,cb_cls,field_name,"I", &fid);
    //LOG_E(THIS_FILE, "Set_natcb_INT_value: fid =%d", fid);        
    env->SetIntField(obj, fid, value);
    return 0;
}

#if 0
void Call_java_natcb_func(
    int          	call_id,
	int          	event_code,
	char*			event_text,
	int 			status_code,
	char*           status_text,
	int             ua_type,
	char*			session_id,
	char*			user_id,
	char*			device_id,
    int             nat_type,
    int             tnl_type
    )
{
    int         err;
    JNIEnv*     env		=NULL;
    jmethodID   methodid;
    const char*       func_name = "on_natnl_tnl_event";
    const char*       func_sign = "()V";
    jclass      Cb_cls;
    jobject     Cb_obj;
    int         isAttached = 0;
	void*		pEnv=NULL;

    LOG_E(THIS_FILE, "=============================> Call_java_natcb_func()");
    //env = jniData.env;
    
#if PJ_ANDROID==1 || PJ_LINUX==1 || PJ_DARWIN==1
    if ( jniData.vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_4) != JNI_OK)	
#else
	if ( jniData.vm->GetEnv(&pEnv, JNI_VERSION_1_4) != JNI_OK)	
#endif
    {
#if PJ_ANDROID==1 || PJ_LINUX==1 || PJ_DARWIN==1
        int status = jniData.vm->AttachCurrentThread(&env, NULL);  
#else
        int status = jniData.vm->AttachCurrentThread(&pEnv, NULL);  
#endif
        if(status < 0) {
            LOG_E(THIS_FILE, "get env failed, env=%p, errno =%d", env, errno);
            return ;
        }else{
            isAttached = 1;
        }
    } 

#if PJ_ANDROID==1 || PJ_LINUX==1 || PJ_DARWIN==1
#else
		env = (JNIEnv*)pEnv;
#endif
     
    LOG_E(THIS_FILE, "=> member_name =%s, class_name =%s, class_path=%s",
          gcb_member_name, gcb_class_name, gcb_class_path);
    err = get_feild_class_ptr(env, jniData.interfaceObject,                         
                        gcb_member_name,
                        gcb_class_name,
                        gcb_class_path,
                        &Cb_cls, &Cb_obj);

    //jfieldID call_id_fid;        get_fieldid(env,Cb_cls,"call_id","I", &call_id_fid);
    //env->SetIntField(Cb_obj, call_id_fid, 111);
    Set_natcb_INT_value(env,Cb_obj,Cb_cls,"call_id",call_id);
    Set_natcb_INT_value(env,Cb_obj,Cb_cls,"event_code",event_code);
    Set_natcb_INT_value(env,Cb_obj,Cb_cls,"status_code",status_code);
    Set_natcb_INT_value(env,Cb_obj,Cb_cls,"ua_type",ua_type);
    Set_natcb_INT_value(env,Cb_obj,Cb_cls,"nat_type",nat_type);
    Set_natcb_INT_value(env,Cb_obj,Cb_cls,"tnl_type",tnl_type);
    
    set_String_value(env,Cb_cls,Cb_obj,"event_text", event_text);
    set_String_value(env,Cb_cls,Cb_obj,"status_text", status_text);
    set_String_value(env,Cb_cls,Cb_obj,"session_id", session_id);
    set_String_value(env,Cb_cls,Cb_obj,"user_id", user_id);
    set_String_value(env,Cb_cls,Cb_obj,"device_id", device_id);
    
    LOG_E(THIS_FILE, "JNI: event_text = %s, status_text=%s, session_id=%s, user_id=%s, devid=%s",
            event_text, status_text, session_id, user_id, device_id
          );
//    LOG_E(THIS_FILE, "gNatEnv = %p, env = %p", gNatEnv, env);
    Call_java_void_method(env, Cb_cls, Cb_obj, func_name, func_sign);
    if(isAttached) {
        jniData.vm->DetachCurrentThread();
    }
}
#endif

void on_natnl_tnl_event(struct natnl_tnl_event *tnl_event) {
    /*
    LOG_E(THIS_FILE, "on_natnl_tnl_event call_id=%d, "
			     "event_code=%d, event_text=%s, status_code=%d, status_text=%s\n",
		     tnl_event->call_id,
		     tnl_event->event_code,
		     tnl_event->event_text,
		     tnl_event->status_code,
		     tnl_event->status_text);
    */
 
    //Call_java_natcb_func();
    //err = get_methodid(env, gNatcb_cls, func_name, func_sign, &methodid);
    //env->CallVoidMethod(gNatcb_obj, methodid);
    /*
    Call_java_natcb_func(
        tnl_event->call_id,
        tnl_event->event_code,
        tnl_event->event_text,
        tnl_event->status_code,
        tnl_event->status_text,
        tnl_event->ua_type,
        tnl_event->session_id,
        tnl_event->para.remote_info.user_id,        
        tnl_event->para.remote_info.device_id,
        tnl_event->nat_type,
        tnl_event->tnl_type
        );
        */
    LOG_E(THIS_FILE, "Call JCallNatCB");
    #if 1
    JCallNatCB(jNatData.obj_callback, tnl_event);

	// dean : check if app_data is allocated. If true free it.
	if (tnl_event->event_code == NATNL_TNL_EVENT_DEINIT_OK || 
		tnl_event->event_code == NATNL_TNL_EVENT_DEINIT_FAILED) {
			if (tnl_event->app_data) {
				free(tnl_event->app_data);
				tnl_event->app_data == NULL;
			}
	}
        #endif
}


enum NAT_METHOD{
	INIT,
	MAKE_CALL,
	GET_FILE,
	PUT_FILE,
	HANG_UP,
	QUIT
};

void
DumpNatCBbuf(   int          	call_id,
	int          	event_code,
	char*			event_text,
	int 			status_code,
	char*           status_text,
	int             ua_type,
	char*			session_id,
	char*			user_id,
	char*			device_id,
    int             nat_type,
    int             tnl_type)
{
    LOG_E(THIS_FILE, " NatCB buf : call_id =%d", call_id);
    LOG_E(THIS_FILE, " NatCB buf : event_code =%d", event_code);
    LOG_E(THIS_FILE, " NatCB buf : status_code =%d", status_code);
    LOG_E(THIS_FILE, " NatCB buf : ua_type =%d", ua_type);
    LOG_E(THIS_FILE, " NatCB buf : nat_type =%d", nat_type);
    LOG_E(THIS_FILE, " NatCB buf : tnl_type =%d", tnl_type);
    LOG_E(THIS_FILE, " NatCB buf : event_text =%s", event_text);
    LOG_E(THIS_FILE, " NatCB buf : status_text =%s", status_text);
    LOG_E(THIS_FILE, " NatCB buf : session_id =%s", session_id);
    LOG_E(THIS_FILE, " NatCB buf : user_id =%s", user_id);
    LOG_E(THIS_FILE, " NatCB buf : device_id =%s", device_id);

}

// Java NatCallback routine
int 
JCallNatCB(jobject obj_natcb, struct natnl_tnl_event *tnl_event)
{
	int         err = -1;
	JNIEnv*     env		=NULL;    
	jmethodID   methodid;
	const char*       func_name = "on_natnl_tnl_event";
	const char*       func_sign = "()V";

	int         isAttached = 0;
	void*		pEnv=NULL;

	LOG_E(THIS_FILE, "=============================> JCallNatCB()");
	//env = jniData.env;

#if PJ_ANDROID==1 || PJ_LINUX==1 || PJ_DARWIN==1
	if ( jniData.vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_4) != JNI_OK)	
#else
	if ( jniData.vm->GetEnv(&pEnv, JNI_VERSION_1_4) != JNI_OK)	
#endif
	{
#if PJ_ANDROID==1 || PJ_LINUX==1 || PJ_DARWIN==1
		int status = jniData.vm->AttachCurrentThread(&env, NULL);  
#else
		int status = jniData.vm->AttachCurrentThread(&pEnv, NULL);  
#endif
		if(status < 0) {
			LOG_E(THIS_FILE, "get env failed, env=%p, errno =%d", env, errno);
			goto JCallCB_ERROR;
		}else{
			isAttached = 1;
		}
	} 

#if PJ_ANDROID==1 || PJ_LINUX==1 || PJ_DARWIN==1
#else
	env = (JNIEnv*)pEnv;
#endif
#if 0
	LOG_E(THIS_FILE, "=> member_name =%s, class_name =%s, class_path=%s",
		gcb_member_name, gcb_class_name, gcb_class_path);

	jobject Cb_obj;jclass  Cb_cls;
	err = get_feild_class_ptr(env, jniData.interfaceObject,                         
		"mNatCb",
		"NatCb",
		"com/asus/natjni/NatCb",
		&Cb_cls, &Cb_obj);




	//jfieldID call_id_fid;        get_fieldid(env,Cb_cls,"call_id","I", &call_id_fid);
	//env->SetIntField(Cb_obj, call_id_fid, 111);
	LOG_E(THIS_FILE, "Set natcb value callid");
	Set_natcb_INT_value(env,Cb_obj,Cb_cls,"call_id",call_id);
	LOG_E(THIS_FILE, "Set natcb value event_code");
	Set_natcb_INT_value(env,Cb_obj,Cb_cls,"event_code",event_code);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls,"status_code",status_code);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls,"ua_type",ua_type);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls,"nat_type",nat_type);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls,"tnl_type",tnl_type);

	set_String_value(env,Cb_cls,Cb_obj,"event_text", event_text);
	set_String_value(env,Cb_cls,Cb_obj,"status_text", status_text);
	set_String_value(env,Cb_cls,Cb_obj,"session_id", session_id);
	set_String_value(env,Cb_cls,Cb_obj,"user_id", user_id);
	set_String_value(env,Cb_cls,Cb_obj,"device_id", device_id);

	LOG_E(THIS_FILE, "JNI: event_text = %s, status_text=%s, session_id=%s, user_id=%s, devid=%s",
		event_text, status_text, session_id, user_id, device_id
		);
	//    LOG_E(THIS_FILE, "gNatEnv = %p, env = %p", gNatEnv, env);
	Call_java_void_method(env, Cb_cls, Cb_obj, func_name, func_sign);
	if(isAttached) {
		jniData.vm->DetachCurrentThread();
	}
	err = 0;
#else
	jobject Cb_obj;jclass  Cb_cls;
	Cb_obj = jNatData.obj_callback;
	Cb_cls = jNatData.cls_callback;
	DumpNatCBbuf(tnl_event->call_id,
		tnl_event->event_code,
		tnl_event->event_text,
		tnl_event->status_code,
		tnl_event->status_text,
		tnl_event->ua_type,
		tnl_event->session_id,
		tnl_event->para.remote_info.user_id,
		tnl_event->para.remote_info.device_id,
		tnl_event->nat_type,
		tnl_event->tnl_type);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "call_id", tnl_event->call_id);

	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "event_code", tnl_event->event_code);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "status_code", tnl_event->status_code);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "ua_type", tnl_event->ua_type);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "nat_type", tnl_event->nat_type);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "tnl_type", tnl_event->tnl_type);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "ice_retry_count", tnl_event->retry_count.ice);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "dtls_retry_count", tnl_event->retry_count.dtls);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "udt_retry_count", tnl_event->retry_count.udt);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "sctp_retry_count", tnl_event->retry_count.sctp);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "tnl_build_spent_sec", tnl_event->tnl_build_spent_sec);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "stun_last_status", tnl_event->stun_last_status);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls, "turn_last_status", tnl_event->turn_last_status);
	printf("JCallNatCB app_data=%s\n", tnl_event->app_data);
	LOG_E(THIS_FILE, "Set String starts");
	LOG_E(THIS_FILE, "JCallNatCB app_data=%s", tnl_event->app_data);
	Set_natcb_INT_value(env,Cb_obj,Cb_cls,"inst_id",tnl_event->inst_id);
	if(tnl_event->event_text)
		set_String_value(env,Cb_cls,Cb_obj,"event_text", tnl_event->event_text);
	if(tnl_event->status_text)
		set_String_value(env,Cb_cls,Cb_obj,"status_text", tnl_event->status_text);
	if(tnl_event->session_id)
		set_String_value(env,Cb_cls,Cb_obj,"session_id", tnl_event->session_id);
	if(tnl_event->para.remote_info.user_id)
		set_String_value(env,Cb_cls,Cb_obj,"user_id", tnl_event->para.remote_info.user_id);
	if(tnl_event->para.remote_info.device_id)
		set_String_value(env,Cb_cls,Cb_obj,"device_id", tnl_event->para.remote_info.device_id);
	if(tnl_event->para.local_info.version)
		set_String_value(env,Cb_cls,Cb_obj,"CalleeSDKVersion", tnl_event->para.local_info.version);
	if(tnl_event->para.remote_info.version)
		set_String_value(env,Cb_cls,Cb_obj,"CallerSDKVersion", tnl_event->para.remote_info.version);
	if(tnl_event->local_ip)
		set_String_value(env,Cb_cls,Cb_obj,"local_ip", tnl_event->local_ip);
	if(tnl_event->public_ip)
		set_String_value(env,Cb_cls,Cb_obj,"public_ip", tnl_event->public_ip);
	if(tnl_event->app_data)
		set_String_value(env,Cb_cls,Cb_obj,"app_data", (const char *)tnl_event->app_data);
	if(tnl_event->turn_mapped_address)
		set_String_value(env,Cb_cls,Cb_obj,"turn_mapped_address", tnl_event->turn_mapped_address);
	if(tnl_event->stun_status_text)
		set_String_value(env,Cb_cls,Cb_obj,"stun_status_text", tnl_event->stun_status_text);
	if(tnl_event->turn_status_text)
		set_String_value(env,Cb_cls,Cb_obj,"turn_status_text", tnl_event->turn_status_text);
	//	if(mac_address)	set_String_value(env,Cb_cls,Cb_obj,"mac_address",mac_address);
	LOG_E(THIS_FILE, "Set String ends");

	for(int i =0; i<4;i++){
		LOG_E(THIS_FILE, "Calllllllllllllllllllllllllllllllllll  on_natnl_tnl_event port=[%d]=%d",i, tnl_event->upnp_port[i]);
	}
	set_IntArray_value(env,Cb_cls,Cb_obj,"upnp_port",tnl_event->upnp_port, 4);
	LOG_E(THIS_FILE, "Calllllllllllllllllllllllllllllllllll  on_natnl_tnl_event begins");

	env->CallVoidMethod(jNatData.obj_callback, jNatData.md_callback);
	LOG_E(THIS_FILE, "Calllllllllllllllllllllllllllllllllll  on_natnl_tnl_event done");

	if(isAttached) {
		LOG_E(THIS_FILE, "Detach Current Thread");
		jniData.vm->DetachCurrentThread();
	}
#endif
	err = 0;
	return  err;

JCallCB_ERROR:
	LOG_E(THIS_FILE, " Return err %d", err);
	err = -1;
	return err;
}


// route Java NatCfg field
int
JGetStr_fromNatCfg( JNIEnv* env, jobject obj_natcfg, const char* fieldname, char* strbuf, size_t str_len )
{
    jclass natnl_config_Class = env->GetObjectClass(obj_natcfg);
    return get_String_value_c(env, natnl_config_Class,
                           obj_natcfg, fieldname, strbuf, str_len);
}

int
JGetINTValue_fromNatCfg( JNIEnv* env, jobject obj_natcfg, const char* fieldname, int* fieldvalue )
{
    	int     err = -1;
	jclass	natnl_config_Class;	
	if(!fieldname) goto JGETINTVALUE_FROMNATCFG_EXIT; 
    	natnl_config_Class = env->GetObjectClass(obj_natcfg);     
    	err = get_INT_value(env, natnl_config_Class, obj_natcfg, fieldname, fieldvalue);
JGETINTVALUE_FROMNATCFG_EXIT:
    	return err;
}

/* +Roger - Set int to Object */
int
JSetIntToObject(JNIEnv* env, jobject tar_obj, const char* fieldname, int fieldvalue)
{
	int	err = -1;
	jfieldID fieldid;

	jclass tar_cls = env->GetObjectClass(tar_obj);
	if(!tar_cls) return -1;

	err = get_fieldid(env,
                  tar_cls,
                  fieldname,
                  "I", // int, void, String , etc...
                  &fieldid);

	env->SetIntField(tar_obj, fieldid, fieldvalue);
    return err;

}

/* +Roger - Set char to Object */
int
JSetCharToObject(JNIEnv* env, jobject tar_obj, const char* fieldname, const char* fieldvalue)
{
	int	err = -1;
	jfieldID fieldid;

	jclass tar_cls = env->GetObjectClass(tar_obj);
	if(!tar_cls) return -1;

	err = get_fieldid(env,
                  tar_cls,
                  fieldname,
                  "Ljava/lang/String;", // int, void, String , etc...
                  &fieldid);

	if(fieldname && fieldvalue)
		env->SetObjectField(tar_obj, fieldid,  fieldvalue ? env->NewStringUTF(fieldvalue) : NULL);

    return err;

}

/* +Roger - Get Object */
int
JGetObject (JNIEnv*  env, 
			jobject  dest_obj, 
            const char*    tar_class_path,
            const char*    fieldname, 
            jobject*    tar_obj )
{
    jclass  dest_obj_class = env->GetObjectClass(dest_obj);
    return get_Obj(env, dest_obj_class,dest_obj, 
               tar_class_path,
               fieldname,
               tar_obj);    
}

/* +Dean - Set natnl_tnl_port array to Object */
int
JSetTnlPortArrayToObject(JNIEnv* env, jobject tar_obj, const char* fieldname, int tnl_port_cnt, natnl_tnl_port tnl_ports[])
{
	int	err = -1;
	int i;
	jfieldID fieldid;
	jobjectArray tnl_ports_array;
	jmethodID cid;

	jclass tar_cls = env->GetObjectClass(tar_obj);
	if(!tar_cls) return -1;

	jclass tnlPortCls = (env)->FindClass(javaTnlPortsClsPath);
	if (tnlPortCls == NULL) {
		return -1; /* exception thrown */
	}
	cid = env->GetMethodID(tnlPortCls, "<init>", "()V");
	if (cid == NULL) {
		return -2; /* exception thrown */
	}
	tnl_ports_array = env->NewObjectArray(tnl_port_cnt, tnlPortCls, NULL);
	for (i = 0; i < tnl_port_cnt; i++) {
		jobject tnl_port = env->NewObject(tnlPortCls, cid);
		if (tnl_port == NULL) {
			return -3; /* out of memory error thrown */
		}
		JSetCharToObject(env, tnl_port, "lport", tnl_ports[i].lport);
		JSetCharToObject(env, tnl_port, "rport", tnl_ports[i].rport);
		JSetIntToObject(env, tnl_port, "qos_priority", tnl_ports[i].qos_priority);
		JSetIntToObject(env, tnl_port, "disable_flow_control", tnl_ports[i].disable_flow_control);
		env->SetObjectArrayElement(tnl_ports_array, i, tnl_port);
		env->DeleteLocalRef(tnl_port);
	}

	char tnlPortClsPath[64];
	sprintf(tnlPortClsPath, "[%s", JNATTNLPORT_CLASSS_PATH);
	err = get_fieldid(env, tar_cls, "tnl_ports", tnlPortClsPath, &fieldid);

	env->SetObjectField(tar_obj, fieldid, tnl_ports_array);

	env->DeleteLocalRef(tnlPortCls);
	env->DeleteLocalRef(tnl_ports_array);

	return err;
}

/* +Dean - Set natnl_im_port array to Object */
int
JSetImPortArrayToObject(JNIEnv* env, jobject tar_obj, const char* fieldname, int im_port_cnt, natnl_im_port im_ports[])
{
	int	err = -1;
	int i;
	jfieldID fieldid;
	jobjectArray im_ports_array;
	jmethodID cid;
	char imPortClsPath[64];

	jclass tar_cls = env->GetObjectClass(tar_obj);
	if(!tar_cls) return -1;

	if (im_port_cnt == 0)
		return 0;

	jclass imPortCls = (env)->FindClass(javaImPortsClsPath);
	if (imPortCls == NULL) {
		return -1; /* exception thrown */
	}
	cid = env->GetMethodID(imPortCls, "<init>", "()V");
	if (cid == NULL) {
		return -2; /* exception thrown */
	}
	im_ports_array = env->NewObjectArray(im_port_cnt, imPortCls, NULL);
	for (i = 0; i < im_port_cnt; i++) {
		jobject im_port = env->NewObject(imPortCls, cid);
		if (im_port == NULL) {
			return -3; /* out of memory error thrown */
		}
		JSetCharToObject(env, im_port, "dest_device_id", im_ports[i].dest_device_id);
		JSetCharToObject(env, im_port, "lport", im_ports[i].lport);
		JSetCharToObject(env, im_port, "rport", im_ports[i].rport);
		JSetIntToObject(env, im_port, "timeout_sec", im_ports[i].timeout_sec);
		env->SetObjectArrayElement(im_ports_array, i, im_port);
		env->DeleteLocalRef(im_port);
		LOG_E(THIS_FILE, "JSetImPortArrayToObject =(%s,%s,%s,%d)", 
			im_ports[i].dest_device_id, im_ports[i].lport, im_ports[i].rport, im_ports[i].timeout_sec);
	}

	sprintf(imPortClsPath, "[%s", JIMPORT_CLASS_PATH);
	err = get_fieldid(env, tar_cls, "im_ports", imPortClsPath, &fieldid);

	env->SetObjectField(tar_obj, fieldid, im_ports_array);

	env->DeleteLocalRef(imPortCls);
	env->DeleteLocalRef(im_ports_array);

	return err;
}

int
JSetINTValue_toNatCfg( JNIEnv* env, jobject obj_natcfg, const char* fieldname, int fieldvalue )
{
    int         err = -1;
	jfieldID			fieldid;
 
    jclass natnl_config_Class = env->GetObjectClass(obj_natcfg);     
	if(!natnl_config_Class) return -1;
    //err = get_INT_value(env, natnl_config_Class, obj_natcfg, fieldname, fieldvalue);
    //err = set_INT_value(env, natnl_config_Class, obj_natcfg, fieldname, fieldvalue);
	err = get_fieldid(env,
                  natnl_config_Class,
                  fieldname,
                  "I", // int, void, String , etc...
                  &fieldid
                  );

	err =  set_INT_fieldid_value( env, obj_natcfg, fieldid,  fieldvalue);
    return err;
}

int
JGetArrayObj_fromNatCfg( JNIEnv*  env, 
                       jobject  obj_natcfg, 
                       const char*    arr_obj_class_path,
                       const char*    Arrayfieldname, 
                       jobjectArray*    arr_obj )
{
    jclass  natnl_config_Class = env->GetObjectClass(obj_natcfg);    
    return get_Array_Obj( env, natnl_config_Class, obj_natcfg,
               arr_obj_class_path,
               Arrayfieldname,
               arr_obj );
}

int
JGetObj_fromNatCfg (JNIEnv*  env, 
                       jobject  nat_obj, 
                       const char*    target_class_path,
                       const char*    fieldname, 
                       jobject*    obj )
{
    jclass  natnl_config_Class = env->GetObjectClass(nat_obj);
    return get_Obj( env, natnl_config_Class,nat_obj, 
               target_class_path,
               fieldname,
               obj );    
}

// route java LogCfg Class
int
JGetStr_fromLogCfg( JNIEnv* env, jobject obj_logcfg, const char* fieldname, char* strbuf, size_t str_len )
{
    jclass LogCfg_Class = env->GetObjectClass(obj_logcfg);
    return get_String_value_c(env, LogCfg_Class,
                           obj_logcfg, fieldname, strbuf, str_len);
}

int
JGetINTValue_fromLogCfg( JNIEnv* env, jobject obj_logcfg, const char* fieldname, int* fieldvalue )
{
    int err = -1;    
    jclass natnl_config_Class = env->GetObjectClass(obj_logcfg);
    err = get_INT_value(env, natnl_config_Class, obj_logcfg, fieldname, fieldvalue);
    return err;
}

// route java SrvPort
int
JGetStr_fromObj( JNIEnv* env, jobject obj, const char* fieldname, char* strbuf, size_t str_len )
{
	if(!obj || !fieldname || !strbuf || !str_len) return -1;
    jclass obj_class = env->GetObjectClass(obj);
	if(!obj_class) return -1;
    return get_String_value_c(env, obj_class,
                           obj, fieldname, strbuf, str_len);
}

int
JGetINTValue_fromObj( JNIEnv* env, jobject obj, const char* fieldname, int* fieldvalue )
{
    int err = -1;
    jclass ojb_class = env->GetObjectClass(obj);
    err = get_INT_value(env, ojb_class, obj, fieldname, fieldvalue);
    return err;
}



// route java UpnpCfg
int
JGetINTValue_fromUpnpCfg( JNIEnv* env, jobject obj_upnpcfg, const char* fieldname, int* fieldvalue )
{
    int err = -1;
    jclass natnl_config_Class = env->GetObjectClass(obj_upnpcfg);
    err = get_INT_value(env, natnl_config_Class, obj_upnpcfg, fieldname, fieldvalue);
    return err;
}



int
JGetArrayObj_fromUpnpCfg( JNIEnv*  env, 
                       jobject  obj_upnpcfg, 
                       const char*    arr_obj_class_path,
                       const char*    Arrayfieldname, 
                       jobjectArray*    arr_obj )
{
    jclass upnpcfg_Class = env->GetObjectClass(obj_upnpcfg);    
    return get_Array_Obj( env, upnpcfg_Class, obj_upnpcfg,
               arr_obj_class_path,
               Arrayfieldname,
               arr_obj );
}

// route User Port Java Class
int
JGetStr_fromUserPort( JNIEnv* env, jobject obj_userport, const char* fieldname, char* strbuf, size_t str_len )
{
    jclass userport_Class = env->GetObjectClass(obj_userport);
    return get_String_value_c(env, userport_Class,
                           obj_userport, fieldname, strbuf, str_len);
}

#if 1
JNIEXPORT jint JNICALL
NatSetCb( JNIEnv* env, jobject thiz, 
          jstring jcb_class_name,
          jstring jcb_member_name, 
          jstring jcb_class_path)
{
   
//    int         err_step=0;
//    jclass      natcb_cls=0;
//    jfieldID    mNatCb_fieldid =0;
//    int         err = -1;

    LOG_E(THIS_FILE, "SetCb start , env =%p", env);
    //jclass cls = env->GetObjectClass(thiz);
    /*
    gcls = env->FindClass(javaClassPath);
    LOG_E(THIS_FILE, "gcls =%d", gcls);
    mNatCb_fieldid = env->GetFieldID(gcls, "mNatCb", "Lcom/asus/natjni/NatCb;");
    LOG_E(THIS_FILE, "mNatCb_field =%d", mNatCb_fieldid);   
*/
/*
    jclass cls = env->GetObjectClass(jniData.interfaceObject);
    LOG_E(THIS_FILE, "cls =%d", cls);
    mNatCb_fieldid = env->GetFieldID(cls, "mNatCb", "Lcom/asus/natjni/NatCb;");    
    LOG_E(THIS_FILE, "mNatCb_field =%d", mNatCb_fieldid);   
    jobject natcb_obj = env->GetObjectField( jniData.interfaceObject, mNatCb_fieldid);
    LOG_E(THIS_FILE, "natcb_obj =%d, err =%d", natcb_obj, errno);
    if(!natcb_obj) goto NatSetCb_Exit;
    natcb_cls= env->GetObjectClass( natcb_obj);
    LOG_E(THIS_FILE, "natcb_cls =%d", natcb_cls);
    if(!natcb_cls) goto NatSetCb_Exit;
    methodid = env->GetMethodID(natcb_cls, "on_natnl_tnl_event", "()V"); 
    LOG_E(THIS_FILE, "methodid=%d", methodid);
    if(!methodid ) goto NatSetCb_Exit;
    */
    int         err = 0;
    //jclass      Cb_cls;
    //jobject     Cb_obj;
    
    
    memset(gcb_member_name, 0, sizeof(gcb_member_name));
    memset(gcb_class_name, 0, sizeof(gcb_class_name));
    memset(gcb_class_path, 0, sizeof(gcb_class_path));
    JStringToChar(env, jcb_member_name, gcb_member_name, sizeof(gcb_member_name));
    JStringToChar(env, jcb_class_name, gcb_class_name, sizeof(gcb_class_name));
    JStringToChar(env, jcb_class_path, gcb_class_path, sizeof(gcb_class_path));
    /*
    err = get_feild_class_ptr(env, jniData.interfaceObject,                         
                        cb_member_name,
                        cb_class_name,
                        cb_class_path,
                        &Cb_cls, &Cb_obj);
    
    gNatcb_cls = Cb_cls;
    gNatcb_obj = Cb_obj;
    */
    
    //err = get_methodid(env, Cb_cls, "on_natnl_tnl_event", 
    //                     "()V", &methodid);    
    //env->CallVoidMethod(Cb_obj, methodid);

/*
    natcb_cls = env->GetObjectClass(cb_cls);
    if(!natcb_cls) goto NatSetCb_Exit;
    err_step =1;
    // get method name
    methodid = env->GetMethodID(cb_cls, "on_natnl_tnl_event", "()V"); 
    if(!methodid ) goto NatSetCb_Exit;
    err_step =2;
*/
NatSetCb_Exit:
    LOG_E(THIS_FILE, "error =%d", err);
    return err;
}
#else
int
NatSetCb (JNIEnv* env, jobject thiz, jobject obj_jCB)
{
    int err=-1;

    return err;
}
#endif       

int JSetNatCbInfo(JNIEnv* env, jobject obj_jCB)
{
    const char* method_name = "on_natnl_tnl_event";
    const char* method_sign = "()V";
    jNatData.obj_callback = env->NewGlobalRef(obj_jCB);
    jNatData.cls_callback= env->GetObjectClass(obj_jCB);    
    jNatData.cls_callback= (jclass)env->NewGlobalRef(jNatData.cls_callback);
    jNatData.md_callback = env->GetMethodID(jNatData.cls_callback , method_name, method_sign);
    LOG_E(THIS_FILE, "Set Nat CB info");
    return 0;
}

JNIEXPORT jint JNICALL
NatReadTnlTransferSpeed__I(JNIEnv* env, jobject thiz, jint call_id, jobject obj_speed, jint inst_id)
{
	jclass  transfer_speed_class = env->GetObjectClass(obj_speed);
	struct natnl_tnl_transfer_speed transfer_speed;

	transfer_speed.rx_speed = 0;
	transfer_speed.tx_speed = 0;
	int status = natnl_read_tnl_transfer_speed_with_inst_id(call_id, &transfer_speed, inst_id);

	if (status == 0) {
		int         err = -1;
		jfieldID			fieldid;

		err = get_fieldid(env,
			transfer_speed_class,
			"rx_speed",
			"I", // int, void, String , etc...
			&fieldid
			);

		err =  set_INT_fieldid_value( env, obj_speed, fieldid,  transfer_speed.rx_speed);

		err = get_fieldid(env,
			transfer_speed_class,
			"tx_speed",
			"I", // int, void, String , etc...
			&fieldid
			);

		err =  set_INT_fieldid_value( env, obj_speed, fieldid,  transfer_speed.tx_speed);
	}

	return status;
}

JNIEXPORT jint JNICALL
NatReadTnlTransferSpeed(JNIEnv* env, jobject thiz, jint call_id, jobject obj_speed)
{
	return NatReadTnlTransferSpeed__I(env, thiz, call_id, obj_speed, 1);
}

JNIEXPORT jint JNICALL
NatSetTnlTransferSpeedLimit__I(JNIEnv* env, jobject thiz, jint call_id, jobject obj_speed, jint inst_id)
{
	int status;
	jclass  transfer_speed_class = env->GetObjectClass(obj_speed);
	struct natnl_tnl_transfer_speed transfer_speed;
	

	status = get_INT_value(env, transfer_speed_class, obj_speed, "rx_speed" , &transfer_speed.rx_speed);
	if (status != 0)
		return status;

	status = get_INT_value(env, transfer_speed_class, obj_speed, "tx_speed" , &transfer_speed.tx_speed);
	if (status != 0)
		return status;

	status = natnl_set_tnl_transfer_speed_limit_with_inst_id(call_id, transfer_speed, inst_id);

	return status;
}

JNIEXPORT jint JNICALL
NatSetTnlTransferSpeedLimit(JNIEnv* env, jobject thiz, jint call_id, jobject obj_speed)
{
	return NatSetTnlTransferSpeedLimit__I(env, thiz, call_id, obj_speed, 1);
}

JNIEXPORT jint JNICALL
NatDetectNatType(
				  JNIEnv* env, jobject thiz,
				  jstring stun_srv)
{
	char c_stun_srv[128]={0};
	JStringToChar(env, stun_srv, c_stun_srv, sizeof(c_stun_srv));
	return natnl_detect_nat_type(c_stun_srv);
}

JNIEXPORT jint JNICALL
NatSetMaxInstances(JNIEnv* env, jobject thiz, jint max_instance)
{
	int ret = natnl_set_max_instances(max_instance); 
	LOG_E(THIS_FILE, "NatSetMaxInstances...max_instance[%d], ret=[%d]\n", max_instance, ret);
	return ret;

}

JNIEXPORT jint JNICALL
NatTunnelPort__I(JNIEnv* env, jobject thiz, int call_id, int action, int tnl_port_count, jobjectArray obj_tnl_port_array, jint instance_id )
{
#if 1
	if(!tnl_port_count || !obj_tnl_port_array) return -1;
	natnl_tnl_port tnl_ports[MAX_TUNNEL_PORT_COUNT];
	memset(tnl_ports, 0, sizeof(tnl_ports));

	for(int i = 0; i<tnl_port_count ; i++) {
		jobject tnl_ports_element  = env->GetObjectArrayElement(obj_tnl_port_array,i);
		LOG_E(THIS_FILE, "tnl_ports_element pointer =%p", tnl_ports_element);
		if(!tnl_ports_element){
			LOG_E(THIS_FILE, "NO OBJECT");	
			continue;
		}
		jclass  tnl_port_Class  = env->GetObjectClass(tnl_ports_element);
		LOG_E(THIS_FILE, "tnl_port_Class pointer =%p", tnl_port_Class);
		if(!tnl_port_Class){
			LOG_E(THIS_FILE, "NO OBJECT");	
			continue;
		}
		LOG_E(THIS_FILE, "Get lport object");	
		JGetStr_fromObj(env,tnl_ports_element,"lport", tnl_ports[i].lport, sizeof(tnl_ports[i].lport));
		LOG_E(THIS_FILE, "Get rport object");	
		JGetStr_fromObj(env,tnl_ports_element,"rport", tnl_ports[i].rport, sizeof(tnl_ports[i].rport)); 
		LOG_E(THIS_FILE, "Get qos_priority member");	
		JGetINTValue_fromObj(env, tnl_ports_element, "qos_priority", &tnl_ports[i].qos_priority);
		LOG_E(THIS_FILE, "Get disable_flow_control member");	
		JGetINTValue_fromObj(env, tnl_ports_element, "disable_flow_control", &tnl_ports[i].disable_flow_control);
		LOG_E(THIS_FILE, "Get speed_limit member");	
		JGetINTValue_fromObj(env, tnl_ports_element, "speed_limit", &tnl_ports[i].speed_limit);
		LOG_E(THIS_FILE, "Get rip member");
		JGetStr_fromObj(env,tnl_ports_element,"rip", tnl_ports[i].rip, sizeof(tnl_ports[i].rip)); 

		LOG_E(THIS_FILE, "NatTunnelPort__I... add [%i] (lport,rport,qos_priority,disable_flow_control,speed_limit)=(%s,%s,%d,%d,%d,%s)", i, 
			tnl_ports[i].lport, tnl_ports[i].rport, tnl_ports[i].qos_priority, tnl_ports[i].disable_flow_control, tnl_ports[i].speed_limit, tnl_ports[i].rip);
	}


#endif
    
	return natnl_tunnel_port_with_inst_id( call_id, action , tnl_port_count, tnl_ports,  instance_id );

}

JNIEXPORT jint JNICALL
NatTunnelPort(JNIEnv* env, jobject thiz, int call_id, int action, int tnl_port_count, jobjectArray obj_tnl_port_array)
{
	return NatTunnelPort__I(env, thiz,  call_id, action , tnl_port_count, obj_tnl_port_array,  1 );
}

JNIEXPORT jint JNICALL
NatInstantMsgPort__I(JNIEnv* env, jobject thiz, int action, int im_port_count, jobjectArray obj_im_port_array, jint instance_id )
{
#if 1
	int ret;
	if(!im_port_count || !obj_im_port_array) return -1;
	natnl_im_port im_ports[MAX_TUNNEL_PORT_COUNT];
	memset(im_ports, 0, sizeof(im_ports));

	for(int i = 0; i<im_port_count ; i++) {
		jobject im_ports_element  = env->GetObjectArrayElement(obj_im_port_array,i);
		LOG_E(THIS_FILE, "tnl_ports_element pointer =%p", im_ports_element);
		if(!im_ports_element){
			LOG_E(THIS_FILE, "NO OBJECT");	
			continue;
		}
		jclass  im_port_Class  = env->GetObjectClass(im_ports_element);
		LOG_E(THIS_FILE, "tnl_port_Class pointer =%p", im_port_Class);
		if(!im_port_Class){
			LOG_E(THIS_FILE, "NO OBJECT");	
			continue;
		}
		LOG_E(THIS_FILE, "Get dest_device_id object");	
		JGetStr_fromObj(env, im_ports_element,"dest_device_id", im_ports[i].dest_device_id, sizeof(im_ports[i].dest_device_id));
		LOG_E(THIS_FILE, "Get lport object");	
		JGetStr_fromObj(env, im_ports_element,"lport", im_ports[i].lport, sizeof(im_ports[i].lport));
		LOG_E(THIS_FILE, "Get rport object");	
		JGetStr_fromObj(env, im_ports_element,"rport", im_ports[i].rport, sizeof(im_ports[i].rport)); 
		LOG_E(THIS_FILE, "Get qos_priority member");	
		JGetINTValue_fromObj(env, im_ports_element, "timeout_sec", &im_ports[i].timeout_sec);

		LOG_E(THIS_FILE, "NatInstantMsgPort__I... action [%i] (dest_device_id,lport,rport,timeout_sec)=(%s,%s,%s,%d)", 
			i, im_ports[i].dest_device_id, im_ports[i].lport, im_ports[i].rport, im_ports[i].timeout_sec);
	}


#endif

	ret = natnl_instant_msg_port_with_inst_id( action , im_port_count, im_ports,  instance_id );
	if (ret != 0)
		return ret;

	jclass imPortCls = (env)->FindClass(javaImPortsClsPath);
	if (imPortCls == NULL) {
		return -1; /* exception thrown */
	}

	for(int i = 0; i<im_port_count ; i++) {
		jobject im_ports_element  = env->GetObjectArrayElement(obj_im_port_array,i);
		LOG_E(THIS_FILE, "tnl_ports_element pointer =%p", im_ports_element);
		if(!im_ports_element){
			LOG_E(THIS_FILE, "NO OBJECT");	
			continue;
		}
		jclass  im_port_Class  = env->GetObjectClass(im_ports_element);
		LOG_E(THIS_FILE, "tnl_port_Class pointer =%p", im_port_Class);
		if(!im_port_Class){
			LOG_E(THIS_FILE, "NO OBJECT");	
			continue;
		}
		set_String_value(env, imPortCls, im_ports_element, "lport", im_ports[i].lport);	

		LOG_E(THIS_FILE, "NatInstantMsgPort__I... action [%i] (dest_device_id,lport,rport,timeout_sec)=(%s,%s,%s,%d)", 
			i, im_ports[i].dest_device_id, im_ports[i].lport, im_ports[i].rport, im_ports[i].timeout_sec);
	}

	return ret;

}

JNIEXPORT jint JNICALL
NatInstantMsgPort(JNIEnv* env, jobject thiz, int action, int im_port_count, jobjectArray obj_im_port_array)
{
	return NatInstantMsgPort__I(env, thiz, action, im_port_count, obj_im_port_array,  1 );
}

JNIEXPORT jint JNICALL
NatPoolDump__I(JNIEnv* env, jobject thiz , int detail,jint instance_id)
{
	return natnl_pool_dump_with_inst_id( detail, instance_id);

}

JNIEXPORT jint JNICALL
NatPoolDump(JNIEnv* env, jobject thiz , int detail )
{
	return natnl_pool_dump( detail );

}

#if 0 
JNIEXPORT jint JNICALL
NatSendIM( JNIEnv* env, jobject thiz )
{
	return 10;
} 
#else
JNIEXPORT jint JNICALL
NatSendIM( JNIEnv* env, jobject thiz, jobject obj_im ) 
{
	int err =-1;
	jclass cls_im= env->GetObjectClass(obj_im);	
	// get rport	
	int rport;
	err = get_INT_value(env, cls_im, obj_im, "rport" , &rport);
	// get deviceid
	char str_devid[128]={0};
	err = get_String_value_c(env, cls_im, obj_im, "dest_device_id", str_devid, sizeof(str_devid));
	// get msg_content
	jstring j_msg_content;
	err = get_String_value_j(env, cls_im, obj_im, "msg_content", &j_msg_content);
	// get msg_len
	int msg_len = get_jstr_len(env, j_msg_content);
	// malloc msg_content char
	char* msg_content = (char* ) malloc(msg_len +1); 
	memset(msg_content, 0, msg_len+1);
	JStringToChar(env, j_msg_content, msg_content, msg_len+1);
	// prepare 128 byte for resp_msg
#define RESP_LEN_INIT 128
	int resp_len= RESP_LEN_INIT;
	char* resp_msg = (char*) malloc(resp_len);
	memset(resp_msg, 0, RESP_LEN_INIT);
	int last_len = resp_len;
	while( (err = natnl_send_instant_msg(str_devid, msg_len, msg_content, rport, &resp_len, resp_msg)) == 70019 ){		
		if(resp_len> last_len)  {
			if(resp_msg) free(resp_msg);			
			resp_msg = (char*)malloc(++resp_len);			
		}else break;
	}	
	if(!err){
		set_String_value(env, cls_im, obj_im, "resp_msg", resp_msg);
		if(msg_content) free(msg_content);
		if(resp_msg)	free(resp_msg);
	}
	return err;
}
#endif
JNIEXPORT jint JNICALL
NatSendIMToRemoteProcess( JNIEnv* env, jobject thiz, jobject obj_im ) 
{
	int err =-1;
	jclass cls_im= env->GetObjectClass(obj_im);	
	// get rport	
	jstring j_proc_name;
	err = get_String_value_j(env, cls_im, obj_im, "process_name", &j_proc_name);
	int proc_name_len = get_jstr_len(env, j_proc_name);
	// malloc msg_content char
	char* proc_name = (char* ) malloc(proc_name_len +1); 
	memset(proc_name, 0, proc_name_len+1);
	JStringToChar(env, j_proc_name, proc_name, proc_name_len+1);
	// get deviceid
	char str_devid[128]={0};
	err = get_String_value_c(env, cls_im, obj_im, "dest_device_id", str_devid, sizeof(str_devid));
	// get msg_content
	jstring j_msg_content;
	err = get_String_value_j(env, cls_im, obj_im, "msg_content", &j_msg_content);
	// get msg_len
	int msg_len = get_jstr_len(env, j_msg_content);
	// malloc msg_content char
	char* msg_content = (char* ) malloc(msg_len +1); 
	memset(msg_content, 0, msg_len+1);
	JStringToChar(env, j_msg_content, msg_content, msg_len+1);
	// prepare 128 byte for resp_msg
#define RESP_LEN_INIT 128
	int resp_len= RESP_LEN_INIT;
	char* resp_msg = (char*) malloc(resp_len);
	memset(resp_msg, 0, RESP_LEN_INIT);
	int last_len = resp_len;
	while( (err = natnl_send_instant_msg_to_remote_process(str_devid, msg_len, msg_content, proc_name, &resp_len, resp_msg)) == 70019 ){		
		if(resp_len> last_len)  {
			if(resp_msg) free(resp_msg);			
			resp_msg = (char*)malloc(++resp_len);			
		}else break;
	}	
	if(!err){
		set_String_value(env, cls_im, obj_im, "resp_msg", resp_msg);
		if(proc_name)	free(proc_name);
		if(msg_content) free(msg_content);
		if(resp_msg)	free(resp_msg);
	}
	return err;
}

JNIEXPORT jint JNICALL
NatReadTnlStatus(JNIEnv* env, jobject thiz, int call_id)
{
	return natnl_read_tnl_status(call_id);
}

JNIEXPORT jint JNICALL
NatReadTnlInfo__I(JNIEnv* env, jobject thiz, int call_id,jobject obj_tnlinfo, jint instance_id)
{
	LOG_E(THIS_FILE, "NatReadTnlInfo_With_Inst_Id");
	int err = -1;
	
	struct	natnl_tnl_info	tnl_info;

	err = natnl_read_tnl_info_with_inst_id(call_id, &tnl_info, instance_id);

	JSetIntToObject(env, obj_tnlinfo, "state", tnl_info.state);
	if (tnl_info.state_text)
		JSetCharToObject(env, obj_tnlinfo, "state_text", tnl_info.state_text);
	JSetIntToObject(env, obj_tnlinfo, "status_code", tnl_info.status_code);
	if (tnl_info.status_text)
		JSetCharToObject(env, obj_tnlinfo, "status_text", tnl_info.status_text);
	JSetIntToObject(env, obj_tnlinfo, "stun_last_status", tnl_info.stun_last_status);
	if (tnl_info.stun_status_text)
		JSetCharToObject(env, obj_tnlinfo, "stun_status_text", tnl_info.stun_status_text);
	JSetIntToObject(env, obj_tnlinfo, "turn_last_status", tnl_info.turn_last_status);
	if (tnl_info.turn_status_text)
		JSetCharToObject(env, obj_tnlinfo, "turn_status_text", tnl_info.turn_status_text);
	
	if(err == 0) {
		JSetIntToObject(env, obj_tnlinfo, "inst_id", tnl_info.inst_id);
		JSetIntToObject(env, obj_tnlinfo, "call_id", tnl_info.call_id);
		JSetIntToObject(env, obj_tnlinfo, "ua_type", tnl_info.ua_type);
		JSetCharToObject(env, obj_tnlinfo, "session_id", tnl_info.session_id);
		JSetIntToObject(env, obj_tnlinfo, "tnl_type", tnl_info.tnl_type);

		jobject obj_para = NULL;
		jobject obj_remote = NULL;
		jobject obj_local = NULL;
		jobject obj_retry_count = NULL;

		JGetObject(env, obj_tnlinfo, JPARAINFO_CLASS_PATH, "para", &obj_para);

		JGetObject(env, obj_para, JREMOTE_CLASS_PATH, "remote_info", &obj_remote);
		JSetCharToObject(env, obj_remote, "device_id", tnl_info.para.remote_info.device_id);
		JSetCharToObject(env, obj_remote, "version", tnl_info.para.remote_info.version);

		JGetObject(env, obj_para, JLOCAL_CLASS_PATH, "local_info", &obj_local);
		JSetCharToObject(env, obj_local, "device_id", tnl_info.para.local_info.device_id);
		JSetCharToObject(env, obj_local, "version", tnl_info.para.local_info.version);

		JGetObject(env, obj_tnlinfo, JRETRYCNT_CLASS_PATH, "retry_count", &obj_retry_count);
		if (obj_retry_count) {
			JSetIntToObject(env, obj_retry_count, "ice", tnl_info.retry_count.ice);
			JSetIntToObject(env, obj_retry_count, "dtls", tnl_info.retry_count.dtls);
			JSetIntToObject(env, obj_retry_count, "udt", tnl_info.retry_count.udt);
			JSetIntToObject(env, obj_retry_count, "sctp", tnl_info.retry_count.sctp);
		}
		JSetIntToObject(env, obj_tnlinfo, "tnl_build_spent_sec", tnl_info.tnl_build_spent_sec);
	}
	return err;
}

JNIEXPORT jint JNICALL
NatReadTnlInfo(JNIEnv* env, jobject thiz, int call_id, jobject obj_tnlinfo)
{
  LOG_E(THIS_FILE, "NatReadTnlInfo");
  return NatReadTnlInfo__I(env, thiz, call_id, obj_tnlinfo, 1);
}


JNIEXPORT jint JNICALL
//Java_com_asus_natjni_NatJni_NatLibInit( JNIEnv* env, jobject thiz ) 
NatLibInit3( JNIEnv* env, jobject thiz, jobject obj_natcfg, jobject obj_jCB, jstring app_data ) 
{      
	//get_java_natnlcb_methodid(env);    
	int ret;
	int instance_id;
	jsize len = 0;
	char *s_app_data = NULL;
	if (app_data) {
		len = GetJStrLen(env, app_data);
		s_app_data = len ? (char *)malloc(len+1) : NULL;
		memset(s_app_data, 0, len+1);
		JStringToChar(env, app_data, s_app_data, len);
	}
	if (obj_jCB)
		JSetNatCbInfo(env,obj_jCB);
	printf("NatLibInit2 s_app_data=%s, len=%d\n", s_app_data, len+1);
	LOG_E(THIS_FILE, "NatLibInit2 s_app_data=%s, len=%d", s_app_data, len+1);
	natnl_callback.on_natnl_tnl_event = NULL;   	
	if (obj_jCB) {
		natnl_callback.on_natnl_tnl_event = &on_natnl_tnl_event;  
		ret = natnl_lib_init_with_inst_id3(  &natnl_config, &instance_id, &natnl_callback, (void *)s_app_data);
	} else
		ret = natnl_lib_init_with_inst_id2(  &natnl_config, &instance_id, (void *)s_app_data);
	if(ret <0) return ret;
	ret = JSetINTValue_toNatCfg(env, obj_natcfg, "instance_id", instance_id );
	printf("JSetObjValue_toNatCfg set_String_value()=%d\n", ret);
	LOG_E(THIS_FILE, "JSetObjValue_toNatCfg set_String_value()=%d", ret);
	ret = JSetImPortArrayToObject(env, obj_natcfg, "im_ports", natnl_config.im_port_count, natnl_config.im_ports);
	if(ret <0) return ret;
	LOG_E(THIS_FILE, "JSetImPortArrayToObject");

	return ret;	
}

JNIEXPORT jint JNICALL
//Java_com_asus_natjni_NatJni_NatLibInit( JNIEnv* env, jobject thiz ) 
NatLibInit2( JNIEnv* env, jobject thiz, jobject obj_natcfg, jstring app_data ) 
{
	return NatLibInit3(env, thiz, obj_natcfg, NULL, app_data);	
}

JNIEXPORT jint JNICALL
NatLibInit( JNIEnv* env, jobject thiz, jobject obj_natcfg ) 
{      
	return NatLibInit3(env, thiz, obj_natcfg, NULL, NULL);	
}


JNIEXPORT jint JNICALL
NatMakeCall__I( JNIEnv* env, jobject thiz , jstring user_id, jstring jcallee, jint timeout, jint use_sctp, jint tnl_port_cnt, 
			   jobjectArray objarray_tnl_ports, jint instance_id, jstring jcaller_device_pwd, jobject obj_info) 
{
	char	s_user_id[128]={0};
	char	callee[MAX_ID_LEN]={0};
	char	caller_device_pwd[MAX_ID_LEN]={0};
	struct	natnl_tnl_info	tnl_info;
	if(!tnl_port_cnt || !objarray_tnl_ports || !jcallee ) return -1;
	JStringToChar(env, user_id, s_user_id, sizeof(s_user_id)  );
	JStringToChar(env, jcallee, callee, sizeof(callee)  );
	JStringToChar(env, jcaller_device_pwd, caller_device_pwd, sizeof(caller_device_pwd)  );
    LOG_E(THIS_FILE, "calleeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee = %s, user_id=%s", callee, s_user_id);
	natnl_tnl_port tnl_ports[MAX_TUNNEL_PORT_COUNT];
	memset(tnl_ports, 0, sizeof(tnl_ports));
	for(int i = 0; i<tnl_port_cnt ; i++) {
	   jobject tnl_ports_element  = env->GetObjectArrayElement(objarray_tnl_ports,i);
			LOG_E(THIS_FILE, "tnl_ports_element pointer =%p", tnl_ports_element);
	   if(!tnl_ports_element){
			LOG_E(THIS_FILE, "NO OBJECT");	
			continue;
	   }
	   jclass  tnl_port_Class  = env->GetObjectClass(tnl_ports_element);
			LOG_E(THIS_FILE, "tnl_port_Class pointer =%p", tnl_port_Class);
	   if(!tnl_port_Class){
			LOG_E(THIS_FILE, "NO OBJECT");	
			continue;
	   }
		LOG_E(THIS_FILE, "Get lport member");	
	    JGetStr_fromObj(env,tnl_ports_element,"lport", tnl_ports[i].lport, sizeof(tnl_ports[i].lport));
		LOG_E(THIS_FILE, "Get rport member");	
		JGetStr_fromObj(env,tnl_ports_element,"rport", tnl_ports[i].rport, sizeof(tnl_ports[i].rport)); 
		LOG_E(THIS_FILE, "Get qos_priority member");	
		JGetINTValue_fromObj(env, tnl_ports_element, "qos_priority", &tnl_ports[i].qos_priority);
		LOG_E(THIS_FILE, "Get disable_flow_control member");	
		JGetINTValue_fromObj(env, tnl_ports_element, "disable_flow_control", &tnl_ports[i].disable_flow_control);
		LOG_E(THIS_FILE, "Get speed_limit member");	
		JGetINTValue_fromObj(env, tnl_ports_element, "speed_limit", &tnl_ports[i].speed_limit);
		LOG_E(THIS_FILE, "Get rip member");
		JGetStr_fromObj(env,tnl_ports_element,"rip", tnl_ports[i].rip, sizeof(tnl_ports[i].rip)); 

	   LOG_E(THIS_FILE, "NatMakeCall... add [%i] (lport,rport,qos_priority,disable_flow_control,speed_limit)=(%s,%s,%d,%d,%d,%s)", i, 
		   tnl_ports[i].lport, tnl_ports[i].rport, tnl_ports[i].qos_priority, tnl_ports[i].disable_flow_control, tnl_ports[i].speed_limit, tnl_ports[i].rip);
	}

	int status  = natnl_make_call_with_inst_id2( callee, tnl_port_cnt, tnl_ports, s_user_id, timeout, use_sctp, instance_id, caller_device_pwd, &tnl_info);
	LOG_E(THIS_FILE, "natnl_make_call %d", status);

	JSetIntToObject(env, obj_info, "state", tnl_info.state);
	JSetCharToObject(env, obj_info, "state_text", tnl_info.state_text);
	JSetIntToObject(env, obj_info, "status_code", tnl_info.status_code);
	JSetCharToObject(env, obj_info, "status_text", tnl_info.status_text);
	JSetIntToObject(env, obj_info, "stun_last_status", tnl_info.stun_last_status);
	JSetCharToObject(env, obj_info, "stun_status_text", tnl_info.stun_status_text);
	JSetIntToObject(env, obj_info, "turn_last_status", tnl_info.turn_last_status);
	JSetCharToObject(env, obj_info, "turn_status_text", tnl_info.turn_status_text);

	if(status == 0) {
		JSetIntToObject(env, obj_info, "inst_id", tnl_info.inst_id);
		JSetIntToObject(env, obj_info, "call_id", tnl_info.call_id);
		JSetIntToObject(env, obj_info, "ua_type", tnl_info.ua_type);
		JSetCharToObject(env, obj_info, "session_id", tnl_info.session_id);
		JSetIntToObject(env, obj_info, "tnl_type", tnl_info.tnl_type);

		jobject obj_para = NULL;
		jobject obj_remote = NULL;
		jobject obj_local = NULL;
		jobject obj_retry_count = NULL;

		JGetObject(env, obj_info, JPARAINFO_CLASS_PATH, "para", &obj_para);

		JGetObject(env, obj_para, JREMOTE_CLASS_PATH, "remote_info", &obj_remote);
		JSetCharToObject(env, obj_remote, "device_id", tnl_info.para.remote_info.device_id);
		JSetCharToObject(env, obj_remote, "version", tnl_info.para.remote_info.version);

		JGetObject(env, obj_para, JLOCAL_CLASS_PATH, "local_info", &obj_local);
		JSetCharToObject(env, obj_local, "device_id", tnl_info.para.local_info.device_id);
		JSetCharToObject(env, obj_local, "version", tnl_info.para.local_info.version);

		JGetObject(env, obj_info, JRETRYCNT_CLASS_PATH, "retry_count", &obj_retry_count);
		if (obj_retry_count) {
			JSetIntToObject(env, obj_retry_count, "ice", tnl_info.retry_count.ice);
			JSetIntToObject(env, obj_retry_count, "dtls", tnl_info.retry_count.dtls);
			JSetIntToObject(env, obj_retry_count, "udt", tnl_info.retry_count.udt);
			JSetIntToObject(env, obj_retry_count, "sctp", tnl_info.retry_count.sctp);
		}
		JSetIntToObject(env, obj_info, "tnl_build_spent_sec", tnl_info.tnl_build_spent_sec);
		JSetCharToObject(env, obj_info, "app_data", (char *)tnl_info.app_data);
		JSetCharToObject(env, obj_info, "turn_mapped_address", tnl_info.turn_mapped_address);
		JSetIntToObject(env, obj_info, "tnl_port_cnt", tnl_info.tnl_port_cnt);
		JSetTnlPortArrayToObject(env, obj_info, "tnl_ports", tnl_info.tnl_port_cnt, tnl_info.tnl_ports);
	}
	
	return status;	
}

JNIEXPORT jint JNICALL
NatMakeCall( JNIEnv* env, jobject thiz , jobject obj_ci, jobject obj_info ) 
{
	int status;
	int call_id;
	jobjectArray objarr_tnl_ports;
 	jclass  call_info_Class = env->GetObjectClass(obj_ci);
	jclass  tnl_info_Class;
	char tnl_port_cls_path[64]={0};
	sprintf(tnl_port_cls_path,"[%s", JNATTNLPORT_CLASSS_PATH);
    	status =  get_Array_Obj( env, call_info_Class, obj_ci, 
               tnl_port_cls_path,
               "tnl_ports",
			   &objarr_tnl_ports );
	int timeout = 0;
		status = get_INT_value(env, call_info_Class, obj_ci, "timeout", &timeout);
	int use_sctp = 0;
    	status = get_INT_value(env, call_info_Class, obj_ci, "use_sctp", &use_sctp);
	int tnl_port_cnt=0;
    	status = get_INT_value(env, call_info_Class, obj_ci, "tnl_port_cnt", &tnl_port_cnt);
	int instance_id=1;
    	status = get_INT_value(env, call_info_Class, obj_ci, "instance_id", &instance_id);
	if(!instance_id) instance_id = 1;
	jstring user_id;
	status = get_String_value_j(env, call_info_Class, obj_ci, "UserID", &user_id);
	jstring callee;
	status = get_String_value_j(env, call_info_Class, obj_ci, "CalleeID", &callee);
	
#ifdef VER_2_1_0_114
  jstring caller_device_pwd;
	status = get_String_value_j(env, call_info_Class, obj_ci, "caller_device_pwd", &caller_device_pwd);
   	status =  NatMakeCall__I(env, thiz , user_id, callee, timeout, use_sctp, tnl_port_cnt, objarr_tnl_ports, instance_id, caller_device_pwd, obj_info);
#else
    status =  NatMakeCall__I(env, thiz , user_id, callee, timeout, use_sctp, tnl_port_cnt, objarr_tnl_ports, instance_id, NULL, obj_info);
#endif
	 int         err = -1;
	jfieldID			fieldid;
 
	    //err = get_INT_value(env, natnl_config_Class, obj_natcfg, fieldname, fieldvalue);
	    //err = set_INT_value(env, natnl_config_Class, obj_natcfg, fieldname, fieldvalue);
	
	tnl_info_Class = env->GetObjectClass(obj_info);
	err = get_INT_value(env, tnl_info_Class, obj_info, "call_id", &call_id);

	err = get_fieldid(env,
                  call_info_Class,
                  "ReturnCallID",
                  "I", // int, void, String , etc...
                  &fieldid
                  );
	err =  set_INT_fieldid_value( env, obj_ci, fieldid,  call_id);
	return status;	
}

JNIEXPORT jint JNICALL
NatDeinit__I( JNIEnv* env, jobject thiz, jint instance_id ) 
{
    LOG_E(THIS_FILE, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>Deinit instance =%d", instance_id);
	return natnl_lib_deinit_with_inst_id(instance_id);
}

JNIEXPORT jint JNICALL
NatDeinit( JNIEnv* env, jobject thiz) 
{
    LOG_E(THIS_FILE, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>Deinit");
	return natnl_lib_deinit();
}

JNIEXPORT jint JNICALL
NatDeinitAll( JNIEnv* env, jobject thiz) 
{
	LOG_E(THIS_FILE, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>Deinit All");	
	return natnl_lib_deinit_all();
}

JNIEXPORT jint JNICALL
//Java_com_asus_natjni_NatJni_NatHangupcall( JNIEnv* env, jobject thiz ) 
NatHangupcall__I( JNIEnv* env, jobject thiz, jint callee_id, jint instance_id  ) 
{
	//return natnl_hangup_call(g_call_id);
    LOG_E(THIS_FILE, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>callee id =%d", callee_id);

    return natnl_hangup_call_with_inst_id(callee_id, instance_id);

}

JNIEXPORT jint JNICALL
//Java_com_asus_natjni_NatJni_NatHangupcall( JNIEnv* env, jobject thiz ) 
NatHangupcall( JNIEnv* env, jobject thiz, jint callee_id) 
{
	//return natnl_hangup_call(g_call_id);
    LOG_E(THIS_FILE, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>callee id =%d", callee_id);

    return natnl_hangup_call(callee_id);

}

JNIEXPORT jint JNICALL
NatRegDevice__I(jint instance_id)
{
	return natnl_reg_device_with_inst_id(instance_id);
}

JNIEXPORT jint JNICALL
NatRegDevice()
{
	return natnl_reg_device();
}


JNIEXPORT jint JNICALL
NatUnRegDevice__I(jint instance_id)
{
	return natnl_unreg_device_with_inst_id(instance_id);
}

JNIEXPORT jint JNICALL
NatUnRegDevice()
{
	return natnl_unreg_device();
}

JNIEXPORT jint JNICALL
//Java_com_asus_natjni_NatJni_NatSetInfo(
NatSetCfgObj(JNIEnv* env, jobject thiz ,  
          jstring jclass_name,
          jstring jfield_name, 
          jstring jclass_path)
{
    jclass  cfg_cls;
    jobject cfg_obj;   
    
    char class_name[128];memset(class_name, 0, sizeof(class_name));
    char field_name[128];memset(field_name, 0, sizeof(field_name));
    char class_path[128];memset(class_path, 0, sizeof(class_path));
    int err;
    LOG_E(THIS_FILE, "call get_feild_class_ptr");
    
    err = get_feild_class_ptr(env, jniData.interfaceObject,                         
                              JStringToChar(env, jfield_name, field_name, sizeof(field_name)),
                              JStringToChar(env, jclass_name, class_name, sizeof(class_name)),
                              JStringToChar(env, jclass_path, class_path, sizeof(class_path)),
                              &cfg_cls, &cfg_obj);
    LOG_E(THIS_FILE, "call get_INT_value");
    err =  get_INT_value(env, cfg_cls, cfg_obj,"use_turn", &natnl_config.use_turn);
    err =  get_INT_value(env, cfg_cls, cfg_obj,"force_to_use_ice", &natnl_config.force_to_use_ice);
    
    return 0;
}


JNIEXPORT jint JNICALL
NatSetCfg(JNIEnv* env, jobject thiz , jobject obj_natcfg)
{    
    
	LOG_E(THIS_FILE, "NatSetConfig");
	int err =-1;

	JGetINTValue_fromNatCfg( env,  obj_natcfg, "force_to_use_ice", &natnl_config.force_to_use_ice);
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "use_turn", &natnl_config.use_turn);
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "use_stun", &natnl_config.use_stun);
	int tmp_max_calls;
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "max_calls", &tmp_max_calls);
	natnl_config.max_calls = (unsigned)tmp_max_calls;
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "use_tls", &natnl_config.use_tls);    
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "verify_server", &natnl_config.verify_server);    
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "tnl_timeout_sec", &natnl_config.tnl_timeout_sec);    
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "disable_sdp_compress", &natnl_config.disable_sdp_compress);    
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "bandwidth_KBs_limit", &natnl_config.bandwidth_KBs_limit);    
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "is_server_side_app", &natnl_config.is_server_side_app);    
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "idle_timeout_sec", &natnl_config.idle_timeout_sec);    
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "fast_init", &natnl_config.fast_init);    
	JGetStr_fromNatCfg(env,obj_natcfg,"device_id"   ,natnl_config.device_id, sizeof(natnl_config.device_id));
	JGetStr_fromNatCfg(env,obj_natcfg,"device_pwd"  ,natnl_config.device_pwd, sizeof(natnl_config.device_pwd));

	// 2014-09-10. Secure Data options.
	LOG_E(THIS_FILE, "Set enable_secure_data");
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "enable_secure_data", &natnl_config.enable_secure_data);

	LOG_E(THIS_FILE, "Set use_ctp");
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "use_sctp", &natnl_config.use_sctp);

	LOG_E(THIS_FILE, "Set cert");
	JGetStr_fromNatCfg(env, obj_natcfg, "cert", natnl_config.cert, sizeof(natnl_config.cert));

	LOG_E(THIS_FILE, "Set cert_pkey");
	JGetStr_fromNatCfg(env, obj_natcfg, "cert_pkey", natnl_config.cert_pkey, sizeof(natnl_config.cert_pkey));

	LOG_E(THIS_FILE, "Set trusted_ca_certs");
	JGetStr_fromNatCfg(env, obj_natcfg, "trusted_ca_certs", natnl_config.trusted_ca_certs, sizeof(natnl_config.trusted_ca_certs));

	LOG_E(THIS_FILE, "Set verify_server_peer");
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "verify_server_peer", &natnl_config.verify_server_peer);

#ifdef VER_2_1_0_114
	LOG_E(THIS_FILE, "Set sip_trusted_ca_certs");
	JGetStr_fromNatCfg(env, obj_natcfg, "sip_trusted_ca_certs", natnl_config.sip_trusted_ca_certs, sizeof(natnl_config.sip_trusted_ca_certs));

	LOG_E(THIS_FILE, "Set sip_verify_server_peer");
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "sip_verify_server_peer", &natnl_config.sip_verify_server_peer);
#endif

	LOG_E(THIS_FILE, "Set NatConfig Sip Server info 3");
	jobjectArray arr_str_sips=NULL;
	JGetArrayObj_fromNatCfg(env,obj_natcfg,"[Ljava/lang/String;","sip_srv", &arr_str_sips);
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "sip_srv_cnt", &natnl_config.sip_srv_cnt);
	if(!natnl_config.sip_srv_cnt || !arr_str_sips) return -1;
	LOG_E(THIS_FILE, "sip srv cnt =%d", natnl_config.sip_srv_cnt);
	int arrayLen= env->GetArrayLength(arr_str_sips);
	LOG_E(THIS_FILE, "arrayLen =%d", arrayLen);
	for(int i =0; i< natnl_config.sip_srv_cnt;i++){
		jstring jSipSrv_i = (jstring)env->GetObjectArrayElement(arr_str_sips,i);
		strcpy(natnl_config.sip_srv[i], env->GetStringUTFChars(jSipSrv_i,0));
		LOG_E(THIS_FILE, "Sip Srvs %d = [%s]", i , natnl_config.sip_srv[i]);
	}
	LOG_E(THIS_FILE, "Set NatConfig Stun Server info");
	jobjectArray arr_str_stuns=NULL;
	JGetArrayObj_fromNatCfg(env,obj_natcfg,"[Ljava/lang/String;","stun_srv", &arr_str_stuns);
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "stun_srv_cnt", &natnl_config.stun_srv_cnt);
	if(!natnl_config.stun_srv_cnt || !arr_str_stuns) return -1;
	LOG_E(THIS_FILE, "stun srv cnt =%d", natnl_config.stun_srv_cnt);
	for(int i =0; i< natnl_config.stun_srv_cnt;i++){
		jstring jStunSrv_i = (jstring)env->GetObjectArrayElement(arr_str_stuns,i);
		strcpy(natnl_config.stun_srv[i], env->GetStringUTFChars(jStunSrv_i,0));
		LOG_E(THIS_FILE, "Sip Srvs %d = [%s]", i , natnl_config.stun_srv[i]);
	}

	LOG_E(THIS_FILE, "Set NatConfig Turn Server info");
	jobjectArray arr_str_turns=NULL;
	JGetArrayObj_fromNatCfg(env,obj_natcfg, "[Ljava/lang/String;", "turn_srv", &arr_str_turns);
	JGetINTValue_fromNatCfg( env,  obj_natcfg, "turn_srv_cnt", &natnl_config.turn_srv_cnt);
	if(!natnl_config.turn_srv_cnt || !arr_str_turns) return -1;
	LOG_E(THIS_FILE, "turn srv cnt =%d", natnl_config.turn_srv_cnt);
	for(int i =0; i< natnl_config.turn_srv_cnt;i++){
		jstring jTurnSrv_i = (jstring)env->GetObjectArrayElement(arr_str_turns,i);
		strcpy(natnl_config.turn_srv[i], env->GetStringUTFChars(jTurnSrv_i,0));
		LOG_E(THIS_FILE, "Turn Srvs %d = [%s]", i , natnl_config.turn_srv[i]);
	}

	LOG_E(THIS_FILE, "Set UpnpCfg class");
	// set upnpcfg
	jobject upnpcfg_obj=NULL;
	LOG_E(THIS_FILE, "UpnpCfg class path =%s",JUPNPCFG_CLASS_PATH);
	JGetObj_fromNatCfg(env,obj_natcfg,JUPNPCFG_CLASS_PATH,"mUpnpCfg",&upnpcfg_obj);
	//JGetObj_fromNatCfg(env,obj_natcfg,"com/asus/natjni/NatCfg$UpnpCfg","mUpnpCfg",&upnpcfg_obj);
	//JGetObj_fromNatCfg(env,obj_natcfg,"Lcom/asus/natapi/UpnpCfg;","mUpnpCfg",&upnpcfg_obj);
	JGetINTValue_fromUpnpCfg(env,upnpcfg_obj,"flag",&natnl_config.upnp_cfg.flag);
	JGetINTValue_fromUpnpCfg(env,upnpcfg_obj,"user_port_count",&natnl_config.upnp_cfg.user_port_count);
	jobjectArray arr_obj_user_port=NULL;

	char usr_port_arr_cls_path[128];
	memset(usr_port_arr_cls_path, 0, sizeof(usr_port_arr_cls_path));
	sprintf(usr_port_arr_cls_path,"[%s",JUSERPORT_CLASS_PATH);
	JGetArrayObj_fromUpnpCfg(env, upnpcfg_obj, usr_port_arr_cls_path, "usr_port", &arr_obj_user_port);
	JGetINTValue_fromUpnpCfg(env,upnpcfg_obj,"user_port_count",&natnl_config.upnp_cfg.user_port_count);
	for(int i = 0; i<natnl_config.upnp_cfg.user_port_count ; i++) {
		jobject usr_port_obj = env->GetObjectArrayElement(arr_obj_user_port,i);
		if(!usr_port_obj) continue;
		jclass usr_port_Class = env->GetObjectClass(usr_port_obj);
		if(!usr_port_Class) continue;
		JGetStr_fromUserPort(env,usr_port_obj,"local_data",natnl_config.upnp_cfg.user_ports[i].local_data, sizeof(natnl_config.upnp_cfg.user_ports[i].local_data));
		JGetStr_fromUserPort(env,usr_port_obj,"local_ctl",natnl_config.upnp_cfg.user_ports[i].local_ctl, sizeof(natnl_config.upnp_cfg.user_ports[i].local_ctl));
		JGetStr_fromUserPort(env,usr_port_obj,"external_data",natnl_config.upnp_cfg.user_ports[i].external_data, sizeof(natnl_config.upnp_cfg.user_ports[i].external_data));
		JGetStr_fromUserPort(env,usr_port_obj,"external_ctl",natnl_config.upnp_cfg.user_ports[i].external_ctl, sizeof(natnl_config.upnp_cfg.user_ports[i].external_ctl));

		LOG_E(THIS_FILE, "local_data =%s, external_data=%s, local_ctl=%s, external_ctl=%s",
				natnl_config.upnp_cfg.user_ports[i].local_data,
				natnl_config.upnp_cfg.user_ports[i].external_data,
				natnl_config.upnp_cfg.user_ports[i].local_ctl,
				natnl_config.upnp_cfg.user_ports[i].external_ctl
		     );
	}

	LOG_E(THIS_FILE, "NAT Instant Message Port .....1");
	jobjectArray arr_obj_im_port=NULL;
	char im_port_arr_cls_path[128];
	memset(im_port_arr_cls_path, 0, sizeof(im_port_arr_cls_path));
	sprintf(im_port_arr_cls_path,"[%s",JIMPORT_CLASS_PATH);
	LOG_E(THIS_FILE, "NAT Instant Message Port .....2, im_port_arr_cls_path=[%s]", im_port_arr_cls_path);
	JGetINTValue_fromNatCfg(env, obj_natcfg, "im_port_count", &natnl_config.im_port_count);
	LOG_E(THIS_FILE, "NAT Instant Message Port .....3, natnl_config.im_port_count=[%d]", natnl_config.im_port_count);    
	JGetArrayObj_fromNatCfg(env, obj_natcfg, im_port_arr_cls_path, "im_ports", &arr_obj_im_port);
	for(int i = 0; i<natnl_config.im_port_count ; i++) {
		jobject im_port_obj = env->GetObjectArrayElement(arr_obj_im_port,i);
		if(!im_port_obj) continue;
		jclass im_port_class = env->GetObjectClass(im_port_obj);
		if(!im_port_class) continue;
		JGetStr_fromObj(env, im_port_obj, "dest_device_id", natnl_config.im_ports[i].dest_device_id, sizeof(natnl_config.im_ports[i].dest_device_id));
		JGetStr_fromObj(env, im_port_obj, "lport", natnl_config.im_ports[i].lport, sizeof(natnl_config.im_ports[i].lport));
		JGetStr_fromObj(env, im_port_obj, "rport", natnl_config.im_ports[i].rport, sizeof(natnl_config.im_ports[i].rport));
		JGetINTValue_fromObj(env, im_port_obj, "timeout_sec", &natnl_config.im_ports[i].timeout_sec);

		LOG_E(THIS_FILE, "dest_device_id=%s, lport=%s, rport=%s, timeout_sec=%d",
			natnl_config.im_ports[i].dest_device_id,
			natnl_config.im_ports[i].lport,
			natnl_config.im_ports[i].rport,
			natnl_config.im_ports[i].timeout_sec);
	}
	LOG_E(THIS_FILE, "NAT Instant Message Port .....4");

	LOG_E(THIS_FILE, "NAT SEtCFG .....1");

	jobject obj_logcfg=NULL;
	JGetObj_fromNatCfg(env,obj_natcfg, JLOGCFG_CLASS_PATH, "mLogCfg",&obj_logcfg);
	JGetINTValue_fromLogCfg(env, obj_logcfg,"log_level",&natnl_config.log_cfg.log_level);
	LOG_E(THIS_FILE, "NAT SEtCFG .....2. log_level=%d", natnl_config.log_cfg.log_level);
	JGetINTValue_fromLogCfg(env, obj_logcfg,"log_file_flags", (int *)(&natnl_config.log_cfg.log_file_flags));
	LOG_E(THIS_FILE, "NAT SEtCFG .....3. log_file_flags=%d", natnl_config.log_cfg.log_file_flags);
	JGetStr_fromLogCfg(env,obj_logcfg,"log_filename", natnl_config.log_cfg.log_filename, sizeof(natnl_config.log_cfg.log_filename));
	LOG_E(THIS_FILE, "NAT SEtCFG .....4. log_filename=%s", natnl_config.log_cfg.log_filename);
	JGetINTValue_fromLogCfg(env, obj_logcfg,"syslog_facility", &natnl_config.log_cfg.syslog_facility);
	LOG_E(THIS_FILE, "NAT SEtCFG .....5. syslog_facility=%d", natnl_config.log_cfg.syslog_facility);
	JGetINTValue_fromLogCfg(env, obj_logcfg,"log_file_size", &natnl_config.log_cfg.log_file_size);
	LOG_E(THIS_FILE, "NAT SEtCFG .....6. log_file_size=%d", natnl_config.log_cfg.log_file_size);
	JGetINTValue_fromLogCfg(env, obj_logcfg,"log_rotate_number", &natnl_config.log_cfg.log_rotate_number);
	LOG_E(THIS_FILE, "NAT SEtCFG .....7. log_rotate_number=%d", natnl_config.log_cfg.log_rotate_number);
	JGetStr_fromLogCfg(env,obj_logcfg,"log_flag_file", natnl_config.log_cfg.log_flag_file, sizeof(natnl_config.log_cfg.log_flag_file));
	LOG_E(THIS_FILE, "NAT SEtCFG .....8. log_flag_file=%s", natnl_config.log_cfg.log_flag_file);
	JGetINTValue_fromLogCfg(env, obj_logcfg,"disable_console_log", &natnl_config.log_cfg.disable_console_log);
	LOG_E(THIS_FILE, "NAT SEtCFG .....9. disable_console_log=%d", natnl_config.log_cfg.disable_console_log);

	err = 0;

    return err;
}

JNIEXPORT jint JNICALL
NatUpdateCfg__I(JNIEnv* env, jobject thiz , jobject obj_natcfg, jint instance_id)
{
	int err = NatSetCfg(env, thiz, obj_natcfg);
	int status = natnl_update_config_with_inst_id( &natnl_config,  instance_id); 
	return status;	
}

JNIEXPORT jint JNICALL
NatUpdateCfg(JNIEnv* env, jobject thiz , jobject obj_natcfg)
{
	int err = NatSetCfg(env, thiz, obj_natcfg);
	int status = natnl_update_config( &natnl_config); 
	return status;	
}

JNIEXPORT jint JNICALL
NatCallReinvite(JNIEnv* env, jobject thiz , jint callid)
{
	return natnl_call_reinvite(callid);
}

JNIEXPORT jint JNICALL
NatCallReinvite__I(JNIEnv* env, jobject thiz , jint callid, jint inst_id)
{
	return natnl_call_reinvite_with_inst_id(callid, inst_id);
}

JNIEXPORT jstring JNICALL
NatLibVersion(JNIEnv* env)
{
    LOG_E(THIS_FILE, "Get Version >>>>>>>>>>>>>>>>>>>>>>>>>> ");
	char* version = natnl_lib_version();
	jstring jstrBuf = env->NewStringUTF(version);
	return jstrBuf;
}


#if PJ_ANDROID==1
JNIEXPORT __attribute__ ((visibility("default")))
#endif
jint JNICALL
JNI_OnLoad(
	JavaVM *vm,
	void *reserved)
{
	LOG_E(THIS_FILE, "JNI_OnLoad...1");
	JNIEnv *jniEnv = NULL;
	JNINativeMethod methods[] = {
		{	"NatSetMaxInstances",			"(I)I"	, reinterpret_cast<int*>(&NatSetMaxInstances)	},	
		{	"NatPoolDump",					"(I)I"	, reinterpret_cast<int*>(&NatPoolDump)	},	
		{	"NatPoolDump",					"(II)I"	, reinterpret_cast<int*>(&NatPoolDump__I)	},	
		{	"NatRegDevice",					"(I)I"	, reinterpret_cast<int*>(&NatRegDevice__I)	},	
		{	"NatRegDevice",					"()I"	, reinterpret_cast<int*>(&NatRegDevice)	},	
		{	"NatUnRegDevice",				"(I)I"	, reinterpret_cast<int*>(&NatUnRegDevice__I)	},	
		{	"NatUnRegDevice",				"()I"	, reinterpret_cast<int*>(&NatUnRegDevice)	},	
		{	"NatHangupcall",				"(II)I"	, reinterpret_cast<int*>(&NatHangupcall__I)},	
		{	"NatHangupcall",				"(I)I"	, reinterpret_cast<int*>(&NatHangupcall)},	
		{	"NatDeinit",					"(I)I"	, reinterpret_cast<int*>(&NatDeinit__I)	},	
		{	"NatDeinit",					"()I"	, reinterpret_cast<int*>(&NatDeinit)	},	
		{	"NatDeinitAll",					"()I"	, reinterpret_cast<int*>(&NatDeinitAll)	},	
		{	"NatMakeCall",					"(Lcom/asus/natapi/CallInfo;Lcom/asus/natapi/NatTnlInfo;)I"	, reinterpret_cast<int*>(&NatMakeCall)},	
		{	"NatLibInit",					"(Lcom/asus/natapi/NatConfig;)I"	, reinterpret_cast<int*>(&NatLibInit)	},	
		{	"NatLibInit",					"(Lcom/asus/natapi/NatConfig;Ljava/lang/String;)I"	, reinterpret_cast<int*>(&NatLibInit2)	},	
		{	"NatLibInit",					"(Lcom/asus/natapi/NatConfig;Lcom/asus/natapi/NatCallback;Ljava/lang/String;)I"	, reinterpret_cast<int*>(&NatLibInit3)	},	
		{	"NatSendIM",					"(Lcom/asus/natapi/InstantMessage;)I", reinterpret_cast<int*>(&NatSendIM)},
		{	"NatSendIMToRemoteProcess",		"(Lcom/asus/natapi/InstantMessageWithProcName;)I", reinterpret_cast<int*>(&NatSendIMToRemoteProcess)},
		{	"NatReadTnlStatus",				"(I)I", reinterpret_cast<int*>(&NatReadTnlStatus)},
		{	"NatReadTnlInfo",				"(ILcom/asus/natapi/NatTnlInfo;)I",	reinterpret_cast<int*>(&NatReadTnlInfo)},
		{	"NatReadTnlInfo",				"(ILcom/asus/natapi/NatTnlInfo;I)I",	reinterpret_cast<int*>(&NatReadTnlInfo__I)},
		{	"NatSetCfg",					"(Lcom/asus/natapi/NatConfig;)I",	reinterpret_cast<int*>(&NatSetCfg)	},
		{	"NatTunnelPort",				"(III[Lcom/asus/natapi/NatTnlPort;I)I",	reinterpret_cast<int*>(&NatTunnelPort__I)	},
		{	"NatTunnelPort",				"(III[Lcom/asus/natapi/NatTnlPort;)I",	reinterpret_cast<int*>(&NatTunnelPort)	},
        {	"NatInstantMsgPort",			"(II[Lcom/asus/natapi/NatImPort;I)I",	reinterpret_cast<int*>(&NatInstantMsgPort__I)	},
		{	"NatInstantMsgPort",			"(II[Lcom/asus/natapi/NatImPort;)I",	reinterpret_cast<int*>(&NatInstantMsgPort)	},
		{	"NatUpdateCfg",					"(Lcom/asus/natapi/NatConfig;I)I",	reinterpret_cast<int*>(&NatUpdateCfg)	},
		{	"NatReadTnlTransferSpeed",		"(ILcom/asus/natapi/NatTransferSpeed;)I",	reinterpret_cast<int*>(&NatReadTnlTransferSpeed)	},
		{	"NatReadTnlTransferSpeed",		"(ILcom/asus/natapi/NatTransferSpeed;I)I",	reinterpret_cast<int*>(&NatReadTnlTransferSpeed__I)	},
		{	"NatSetTnlTransferSpeedLimit",	"(ILcom/asus/natapi/NatTransferSpeed;)I",	reinterpret_cast<int*>(&NatSetTnlTransferSpeedLimit)	},
		{	"NatSetTnlTransferSpeedLimit",	"(ILcom/asus/natapi/NatTransferSpeed;I)I",	reinterpret_cast<int*>(&NatSetTnlTransferSpeedLimit__I)	},
		{	"NatDetectNatType",				"(Ljava/lang/String;)I",	reinterpret_cast<int*>(&NatDetectNatType)	},
        {	"NatLibVersion",				"()Ljava/lang/String;",	(void*)NatLibVersion	},
	};

	LOG_E(THIS_FILE, "JNI_OnLoad...2");
	if (vm->GetEnv(reinterpret_cast<void**>(&jniEnv), JNI_VERSION_1_4) != JNI_OK)
	{
		return JNI_ERR;
	}	

	LOG_E(THIS_FILE, "JNI_OnLoad...3 env=%p", jniEnv);
	if (IsNULL_PTR(jniEnv)) 
	{
		return JNI_ERR;
	}
	jclass cls = jniEnv->FindClass(javaClassPath);
	LOG_E(THIS_FILE, "JNI_OnLoad...4");
	if (IsNULL_PTR(cls))
	{
		return JNI_ERR;
	}

	LOG_E(THIS_FILE, "JNI_OnLoad...5");
	jmethodID constr = jniEnv->GetMethodID(cls, "<init>", "()V");
	if (IsNULL_PTR(constr)) 
	{
		return JNI_ERR;
	}
	
	LOG_E(THIS_FILE, "JNI_OnLoad...6");
	jobject obj = jniEnv->NewObject(cls, constr);
	if (IsNULL_PTR(obj)) 
	{
		return JNI_ERR;
	}
	
	jobject InterfaceObject = jniEnv->NewGlobalRef(obj);
    jniEnv->RegisterNatives(cls, methods, sizeof(methods)/sizeof(methods[0]));

	memset(&jniData,0,sizeof(JNIDATA));
	jniData.vm = vm;
	jniData.interfaceObject = InterfaceObject; 
	LOG_E(THIS_FILE, "JNI_OnLoad...7");
    
	return JNI_VERSION_1_4;
}
//---------------------------------------------------------------------------


