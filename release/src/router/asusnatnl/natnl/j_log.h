#include <android/log.h>

#define DBG_TAG "Charles_Debug"
#define LOG_D(__title__, ...) do {\
   if (__title__ == NULL)\
   {\
	  __android_log_print(ANDROID_LOG_DEBUG, DBG_TAG,__VA_ARGS__);\
   }\
   else\
   {\
	  __android_log_print(ANDROID_LOG_DEBUG,__title__,__VA_ARGS__);\
   }\
}while(0)

#define LOG_E(__title__,...) do {\
   if (__title__ == NULL)\
   {\
	  __android_log_print(ANDROID_LOG_ERROR, DBG_TAG,__VA_ARGS__);\
   }\
   else\
   {\
	  __android_log_print(ANDROID_LOG_ERROR,__title__,__VA_ARGS__);\
   }\
}while(0)

