/*
 * A log module that can be dynamically controlled by file
 *
 * Copyright (C) 2021, yjh277 <yjh277@126.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdarg.h> 
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <pthread.h>
#include <sys/prctl.h>
#include "list.h"
#include "ypub_log.h"
#include <sys/stat.h>

#define YPUB_LOG_MODULE_MAX     64
#define YPUB_LOG_FILENAME_LEN   64
#define YPUB_LOG_CTLFILE_LEN    1024

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

typedef struct {
    int used;
    YPUB_LOG_LVL_E level;
} ypub_log_level;

typedef struct ypub_log_ctl {
    struct list_head list;
    char file_name[YPUB_LOG_FILENAME_LEN];  //File path for monitoring
    unsigned int mask;                      //Event mask for monitoring
    int wd;                                 //id for monitoring
    int mod_id;
    ypub_log_ctl_pfun pcallback;
} ypub_log_ctl_st, *ypub_log_ctl_sp;

typedef struct ypub_log {
    struct list_head head;
    pthread_mutex_t mutex;
    pthread_t tid;
    int fd;
    unsigned char* pbuf;
    ypub_log_level log_level[YPUB_LOG_MODULE_MAX];
} ypub_log_st, *ypub_log_sp;

static ypub_log_sp g_ypub_log = NULL;

static ypub_log_sp ypub_log_get_handle(void)
{
    return g_ypub_log;
}

static ypub_log_set_handle(ypub_log_sp handle)
{
    g_ypub_log = handle;
}

static int ypub_log_read_file(char* file, char* buf, int len)
{
    FILE *stream;
    int ret;

    if ((stream = fopen(file, "r")) == NULL) {
        fprintf(stderr, "Failed to open file %s\n", file);
        return -1;
    }

    ret = fread(buf, 1, len, stream);

    fclose(stream);

    return ret;
}

static int ypub_log_get_file_size(const char* path)
{
    int filesize = -1;    
    struct stat statbuff;

    if (stat(path, &statbuff) < 0) {
        return filesize;
    } else {
        filesize = statbuff.st_size;
    }

    return filesize;
}


static int ypub_log_callpfun(ypub_log_ctl_sp pctl, struct inotify_event *event)
{
    char *pbuf;
    int level = 0;
    int len;
    int filesize;

    if (event->mask & IN_MODIFY) {
        if (event->mask & IN_ISDIR) {
            return -1;
        }

        filesize = ypub_log_get_file_size(pctl->file_name);
        if (filesize <= 0) {
            fprintf(stderr, "get file size error[%d]\n", filesize);
            return -1;
        }
        pbuf = malloc(filesize + 1);
        if (!pbuf) {
            return -1;
        }

        memset(pbuf, 0, filesize + 1);
        len = ypub_log_read_file(pctl->file_name, pbuf, filesize);
        pctl->pcallback(pctl->mod_id, pbuf, len);
        free(pbuf);
    }

    return 0;
}
 
static void ypub_log_process_msg(ypub_log_sp plog)
{
    int idx = 0;
    int length = 0;
    struct inotify_event *event = NULL;
    ypub_log_ctl_sp pctl;

    length = read(plog->fd, plog->pbuf, BUF_LEN);
    if (length < 0) {
        fprintf(stderr, "Failed to read file\n");
        return;
    }

    while (idx < length) {
        event = (struct inotify_event *)(plog->pbuf + idx);
        list_for_each_entry(pctl, &(plog->head), list) {
            if ((event->wd == pctl->wd) && (event->mask & pctl->mask)) {
                ypub_log_callpfun(pctl, event);
                break;
            }
        }

        idx += (EVENT_SIZE + event->len);
    }
    memset(plog->pbuf, 0, BUF_LEN);
}
 
static void* ypub_log_inotify_task(void* arg)
{
    ypub_log_sp plog;
    fd_set rset;
    int nready;

    plog = (ypub_log_sp)arg;

    prctl(PR_SET_NAME, "inotify_task");

    FD_ZERO(&rset);
    FD_SET(plog->fd, &rset);

    while (1) {
        nready = select(plog->fd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            fprintf(stderr, "error select !\n");
            break;
        } else if (nready == 0) {
            fprintf(stderr, "timeout!\n");
            continue;
        }

        ypub_log_process_msg(plog);
    }

    return NULL;
}

static int ypub_log_create_file(char* pfile)
{
    FILE * fp;

    if (pfile == NULL || strlen(pfile) == 0) {
        return YPUB_LOG_EFILENAME;
    }

    fp = fopen(pfile, "w+");
    if (!fp) {
        return YPUB_LOG_ENOENT;
    }
    fclose(fp);

    return YPUB_LOG_SUCC;
}

static int ypub_log_add_watch(int fd, ypub_log_ctl_sp pctl)
{
    ypub_log_create_file(pctl->file_name);
    pctl->wd = inotify_add_watch(fd, pctl->file_name, pctl->mask);
    if (pctl->wd == -1) {
        return YPUB_LOG_EADDWATCH;
    }

    return YPUB_LOG_SUCC;
}

static int ypub_log_init(void)
{
    ypub_log_sp handle;
    struct list_head *n, *pos;
    ypub_log_ctl_sp pctl;

    if (ypub_log_get_handle()) {
        return YPUB_LOG_SUCC;
    }

    handle = (ypub_log_sp)malloc(sizeof(ypub_log_st));
    if (!handle) {
        return YPUB_LOG_ENOMEM;
    }
    ypub_log_set_handle(handle);
    memset(handle, 0, sizeof(ypub_log_st));

    handle->pbuf = (unsigned char*)malloc(BUF_LEN);
    if (!(handle->pbuf)) {
        free(handle);
        return YPUB_LOG_ENOMEM;
    }
    INIT_LIST_HEAD(&(handle->head));
    pthread_mutex_init(&(handle->mutex), NULL);

    handle->fd = inotify_init();
    if (handle->fd < 0) {
        pthread_mutex_destroy(&(handle->mutex));
        free(handle->pbuf);
        free(handle);
        return YPUB_LOG_ESYSCALL;
    }

    pthread_mutex_lock(&(handle->mutex));
    list_for_each_entry(pctl, &(handle->head), list) {
        ypub_log_add_watch(handle->fd, pctl);
    }
    pthread_mutex_unlock(&(handle->mutex));

    if ((pthread_create(&(handle->tid), NULL, ypub_log_inotify_task, handle)) == -1) {
        return -1;
    }
 
    return 0;
}

void ypub_log_trace(int mod_id, YPUB_LOG_LVL_E lvl, const char* file, int line, 
                    const char* function, const char* szmsg,...)
{
    va_list args;
    ypub_log_sp plog = ypub_log_get_handle();
    if (!plog) {
        return;
    }

    if (!plog->log_level[mod_id].used) {
        return;
    }

    if (lvl <= plog->log_level[mod_id].level) {
        printf("<%s, %d, %s>:", file, line, function);
        va_start(args,szmsg);
        vprintf(szmsg,args);
        va_end(args);
    }
}

void ypub_log_write(int mod_id, YPUB_LOG_LVL_E nlevel, const char* fmt,...)
{
    va_list args;
    ypub_log_sp plog = ypub_log_get_handle();
    if (!plog) {
        return;
    }

    if (nlevel <= plog->log_level[mod_id].level) {
        va_start(args,fmt);
        vprintf(fmt,args);
        va_end(args);
    }
}

int ypub_log_set_dgblvl(int mod_id, YPUB_LOG_LVL_E lvl)
{
    ypub_log_sp plog = ypub_log_get_handle();
    if (!plog) {
        return -1;
    }

    if (plog->log_level[mod_id].used) {
        plog->log_level[mod_id].level = lvl;
    }

    return 0;
}

int ypub_log_regmod(char* mod_name, char* pctlfile, ypub_log_ctl_pfun pfun)
{
    ypub_log_sp plog;
    ypub_log_ctl_sp pctl;
    struct list_head* phead;
    int ret;
    int mod_id;

    if ((pctlfile == NULL) || (pfun == NULL)) {
        return YPUB_LOG_EPARAM;
    }

    if (strlen(pctlfile) > YPUB_LOG_FILENAME_LEN) {
        return YPUB_LOG_EFLENAMETOOLONG;
    }

    plog = ypub_log_get_handle();
    if (!plog) {
        if (ypub_log_init() != YPUB_LOG_SUCC) {
            return ret;
        }
        plog = ypub_log_get_handle();
    }

    for (mod_id = 0; mod_id < YPUB_LOG_MODULE_MAX; mod_id++) {
        if (plog->log_level[mod_id].used == 0) {
            break;
        }
    }

    if (mod_id >= YPUB_LOG_MODULE_MAX) {
        return YPUB_LOG_ENOMODULE;
    }

    pctl = (ypub_log_ctl_sp)malloc(sizeof(ypub_log_ctl_st));
    if (!pctl) {
        return YPUB_LOG_ENOMEM;
    }

    memcpy(pctl->file_name, pctlfile, strlen(pctlfile));
    pctl->mask = IN_MODIFY;
    pctl->wd = -1;
    pctl->pcallback = pfun;
    INIT_LIST_HEAD(&(pctl->list));
    pctl->mod_id = mod_id;
    plog->log_level[mod_id].used = 1;

    pthread_mutex_lock(&(plog->mutex));
    ret = ypub_log_add_watch(plog->fd, pctl);
    if (ret != YPUB_LOG_SUCC) {
        pthread_mutex_unlock(&(plog->mutex));
        return ret;
    }

    list_add_tail(&(pctl->list), &(plog->head));
    pthread_mutex_unlock(&(plog->mutex));

    return mod_id;
}

int ypub_log_ugregmod(int mod_id)
{
    ypub_log_sp plog = ypub_log_get_handle();
    struct list_head *pos, *n;
    ypub_log_ctl_sp pctl;

    pthread_mutex_lock(&(plog->mutex));
    list_for_each_safe(pos, n, &(plog->head)) {
		pctl = list_entry(pos, ypub_log_ctl_st, list);
        if (pctl->mod_id == mod_id) {
            inotify_rm_watch(plog->fd, pctl->wd);
            list_del(&(pctl->list));
            free(pctl);
            plog->log_level[mod_id].used = 0;
            plog->log_level[mod_id].level = 0;
            break;
        }
    }

    pthread_mutex_unlock(&(plog->mutex));

    return YPUB_LOG_SUCC;    
}

