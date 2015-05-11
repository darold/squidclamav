#ifndef __SRV_CLAMAV_H
#define __SRV_CLAMAV_H

#define LOG_URL_SIZE 256

#include <sys/types.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <libgen.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sysexits.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "txt_format.h"

/* util.h */
void xstrncpy(char *, const char *, size_t);
void chomp(char *);
int isPathExists(const char *);
int isFileExists(const char *);
int isPathSecure(const char *);
size_t strlcat(char *dst, const char *src, size_t siz);
size_t xstrnlen(const char *s, size_t n);
char** split( char* str, const char* delim);

/* log.h */
#ifdef __GNUC__
void logit(char *, char *, ...) __attribute__ ((format (printf, 2, 3)));
#else
void logit(char *, char *, ...);
#endif

/* squidclamav.h */
/*************  Default configuration file location  ***********/
#define CONFIG_FILE "squidclamav.conf"

/************* Proxy configuration *************/
#define PROXY_SERVER "127.0.0.1"
#define PROXY_PORT "3128"


/************* Default Clamd configuration *************/
#define CLAMD_SERVER "127.0.0.1" 
#define CLAMD_PORT "3310" 

# ifdef S_SPLINT_S
extern char *strdup (char *s) /*@*/ ;
#endif

#include<stdarg.h>
#include<sys/types.h>
#include<regex.h>
#define LOW_CHAR 32
#define SMALL_CHAR 128
#define LOW_BUFF 256
#define SMALL_BUFF 1024
#define NORMAL_BUFF 4096
#define MAX_URL  8192
#define MAX_LOGIN_SZ 128

struct IN_BUFF {
    char url[MAX_URL];
    char src_address[1050];
    char ident[MAX_LOGIN_SZ];
    char method[LOW_CHAR];
    char ipaddress[16];
    char fqdn[1024];
};

#define WHITELIST    1
#define TRUSTUSER    2
#define TRUSTCLIENT  3
#define ABORT        4
#define ABORTCONTENT 5

#define ACCEL_NORMAL 1
#define ACCEL_START  2
#define ACCEL_END    3

#define PATTERN_ARR_SIZE 32	/* Array of 32 patterns */

struct IP {
    short first;
    short second;
    short third;
};

typedef struct {
    char *pattern;
    int type;
    int flag;
    regex_t regexv;
} SCPattern;

int add_pattern(char *s, int level);
void regcomp_pattern(void);
int load_in_buff(char *);
int simple_pattern_compare(const char *, const int );
int client_pattern_compare(const char *, char *);
int load_patterns(void);
int readFileContent(char *filepath, char *kind);


// compatibility with folks that don't have __FUNCTION__, e.g. solaris
#if defined(__SUNPRO_CC) && !defined(__FUNCTION__)
    #ifdef __func__
        #define __FUNCTION__ __func__
    #else
        #define __FUNCTION__ ""
    #endif
#endif

#define debugs(LEVEL, ARGS...) \
    ci_debug_printf(LEVEL, "%s(%d) %s: ", __FILE__, __LINE__, __FUNCTION__); \
    ci_debug_printf(LEVEL, ARGS)

#ifdef HAVE_CICAP_TEMPLATE
int fmt_malware(ci_request_t *req, char *buf, int len, const char *param);

struct ci_fmt_entry GlobalTable [] = {
    {"%mn", "Malware Name", fmt_malware},
    { NULL, NULL, NULL}
};
#endif

#endif
