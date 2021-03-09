#ifndef _DEBUG_H
#define _DEBUG_H

#define DEBUG

#include "libbb_udhcp.h"
#include <sys/types.h>

#include <stdio.h>
#ifdef SYSLOG
#include <syslog.h>
#endif

#define TAG "udhcpd"

#ifdef SYSLOG
# define LOG(level, str, args...) do { \
                printf("%11.11s, ", #level); \
                printf(str, ## args); \
				printf("\n"); \
				syslog(level, str, ## args); } while(0);
# define OPEN_LOG(name) openlog(name, 0, 0)
#define CLOSE_LOG() closelog()

#elif ANDROID
#include <android/log.h>
# define OPEN_LOG(name)
# define CLOSE_LOG()
# define LOG_EMERG	 ANDROID_LOG_FATAL
# define LOG_ALERT	 ANDROID_LOG_FATAL
# define LOG_CRIT	 ANDROID_LOG_FATAL
# define LOG_WARNING ANDROID_LOG_WARN
# define LOG_ERR	 ANDROID_LOG_ERROR
# define LOG_INFO	 ANDROID_LOG_INFO
# define LOG_DEBUG	 ANDROID_LOG_DEBUG
# define LOG(level, str, args...) {\
                printf("%11.11s, ", #level); \
                printf(str, ## args); \
				printf("\n"); \
                __android_log_print(level, TAG, str, ##args);}

#else
# define LOG_EMERG	"EMERGENCY!"
# define LOG_ALERT	"ALERT!"
# define LOG_CRIT	"critical!"
# define LOG_WARNING	"warning"
# define LOG_ERR	"error"
# define LOG_INFO	"info"
# define LOG_DEBUG	"debug"
# define LOG(level, str, args...) do { printf("%s, ", level); \
				printf(str, ## args); \
				printf("\n"); } while(0)
# define OPEN_LOG(name) do {;} while(0)
#define CLOSE_LOG() do {;} while(0)
#endif

#ifdef DEBUG
# undef DEBUG
# define DEBUG LOG
# define DEBUGGING
#else
# define DEBUG(level, str, args...) do {;} while(0)
#endif

#endif
