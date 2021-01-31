#ifndef _YPUB_LOG_H_
#define _YPUB_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define YPUB_LOG_SUCC               0   //success
#define YPUB_LOG_ENOMEM             -1   //get mem error
#define YPUB_LOG_ESYSCALL           -2   
#define YPUB_LOG_EFILENAME          -3
#define YPUB_LOG_ENOENT             -4
#define YPUB_LOG_EADDWATCH          -5
#define YPUB_LOG_EPARAM             -6
#define YPUB_LOG_EFLENAMETOOLONG    -7
#define YPUB_LOG_EMMODULE           -8
#define YPUB_LOG_ENOINIT            -9
#define YPUB_LOG_ENOMODULE          -10

typedef enum ypub_log_lvl_e {
    YPUB_LOG_ERROR = 0,
    YPUB_LOG_WARN,
    YPUB_LOG_DEBUG,
    YPUB_LOG__END
} YPUB_LOG_LVL_E;

typedef int (*ypub_log_ctl_pfun)(int mod_id, char* pbuf, int len);

void ypub_log_trace(int mod_id, YPUB_LOG_LVL_E lvl, const char* file, int line, 
                    const char* function, const char* szmsg,...);

void ypub_log_write(int mod_id, YPUB_LOG_LVL_E nlevel, const char* fmt,...);

#define YPUB_LOG_DEBUG(mod_id, ...) ypub_log_trace(mod_id, YPUB_LOG_DEBUG,  \
                                        (const char*)__FILE__,      \
                                        (int)__LINE__,              \
                                        (const char*)__FUNCTION__,  \
                                        __VA_ARGS__)

#define YPUB_LOG_WARN(mod_id, ...) ypub_log_trace(mod_id, YPUB_LOG_WARN,  \
                                        (const char*)__FILE__,      \
                                        (int)__LINE__,              \
                                        (const char*)__FUNCTION__,  \
                                        __VA_ARGS__)

#define YPUB_LOG_ERROR(mod_id, ...) ypub_log_trace(mod_id, YPUB_LOG_ERROR,  \
                                        (const char*)__FILE__,      \
                                        (int)__LINE__,              \
                                        (const char*)__FUNCTION__,  \
                                        __VA_ARGS__)

int ypub_log_set_dgblvl(int mod_id, YPUB_LOG_LVL_E lvl);

int ypub_log_regmod(char* mod_name, char* pctlfile, ypub_log_ctl_pfun pfun);

int ypub_log_ugregmod(int mod_id);


#ifdef __cplusplus
}
#endif  /* __cplusplus */
#endif /* _YPUB_LOG_H_ */

