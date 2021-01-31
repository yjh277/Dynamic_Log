#include <stdio.h>
#include <string.h>

#include "ypub_log.h"

int testcallback(int mod_id, char* pbuf, int len)
{
    YPUB_LOG_LVL_E lvl;

    if (memcmp(pbuf, "exit", len) == 0) {
        ypub_log_ugregmod(mod_id);
        return 0;
    }

    lvl = atoi(pbuf);
    ypub_log_set_dgblvl(mod_id, lvl);

    return 0;
}

int main(void)
{
    int mod_id[5];
    int i;
    
    mod_id[0] = ypub_log_regmod("test1", "/tmp/1", testcallback);
    mod_id[1] = ypub_log_regmod("test2", "/tmp/2", testcallback);
    mod_id[2] = ypub_log_regmod("test3", "/tmp/3", testcallback);
    mod_id[3] = ypub_log_regmod("test4", "/tmp/4", testcallback);
    mod_id[4] = ypub_log_regmod("test5", "/tmp/5", testcallback);

    while (1) {
        for (i = 0; i < sizeof(mod_id) / sizeof(mod_id[0]); i++) {
            YPUB_LOG_DEBUG(mod_id[i], "mod_id:%d debug\n", mod_id[i]);
            YPUB_LOG_WARN(mod_id[i], "mod_id:%d warning\n", mod_id[i]);
            YPUB_LOG_ERROR(mod_id[i], "mod_id:%d error\n", mod_id[i]);
        }
        sleep(5);
    }
}

