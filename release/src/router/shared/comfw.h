#ifndef __COMFW_H__
#define __COMFW_H__

#define MAX_CF  4
#define MAX_NAMELEN     128
#define OUTPUT_DIR      "comfw_dir"
#define BUFSIZE         4096
#define COMFW_MAGIC     0x20210816

/*
CF_RTAC68U       // trx            
CF_RTAX58U       // w              
CF_RTAX58U_V2    // pkgtb           
CF_RPAX56        // w               
CF_RPAX58        // pkgtb              
CF_RTAX82_XD6    // w           
CF_RTAX82_XD6S   // w	
CF_TUFAX3000     // w                
CF_TUFAX3000_V2  // pkgtb              
CF_RTAX95Q       // w              
CF_RTAX95QV2     // pkgtb               
CF_RTAX95QV3     // pkgtb               
*/

/* new model must be added after the latest one */
#define COMFW_MODELID {                       \
     MODELID(ASUS_MODEL),                       \
     MODELID(CF_RTAC68U),                    \
     MODELID(CF_RTAX58U),                        \
     MODELID(CF_RTAX58U_V2),                 \
     MODELID(CF_RPAX56),                        \
     MODELID(CF_RPAX58),                        \
     MODELID(CF_RTAX82_XD6),                        \
     MODELID(CF_RTAX82_XD6S),		\
     MODELID(CF_TUFAX3000),                     \
     MODELID(CF_TUFAX3000_V2),                  \
     MODELID(CF_RTAX95Q),                     \
     MODELID(CF_RTAX95QV2),                     \
     MODELID(CF_RTAX95QV3),                     \
     MODELID(MAX_FTYPE),                           \
}

#define MODELID(a)       a
typedef enum COMFW_MODELID comfw_modid_e;
#undef MODELID

#define MODELID(a)       #a
char *comfw_modid_s[] = COMFW_MODELID;
#undef MODELID

typedef struct _comfw
{
        int magic;
        int fw_type[MAX_CF];
        int fw_size[MAX_CF];
	char data[MAX_CF][16];
} comfw_head;

#endif
