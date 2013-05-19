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
#define CONFIG_FILE "/etc/squidclamav.conf"

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

int add_pattern(char *s);
void regcomp_pattern(void);
int load_in_buff(char *);
int simple_pattern_compare(char *, const int );
int client_pattern_compare(char *, char *);
int load_patterns(void);


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

// everything from here down with exception to fmt_malware, is from c-icap, in
// txt_format.c. None if it is in a header. So it must be defined here.

int fmt_none(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_percent(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_remoteip(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_localip(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_icapstatus(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_icapmethod(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_service(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_username(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_request(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_localtime(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_gmttime(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_seconds(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_httpclientip(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_httpserverip(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_http_req_url_o(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_http_req_head_o(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_http_res_head_o(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_icap_req_head(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_icap_res_head(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_req_bytes_rcv(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_req_bytes_sent(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_req_http_bytes_rcv(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_req_http_bytes_sent(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_req_body_bytes_rcv(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_req_body_bytes_sent(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_req_preview_hex(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_req_preview_len(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_logstr(ci_request_t *req_data, char *buf,int len, const char *param);
int fmt_req_attribute(ci_request_t *req_data, char *buf,int len, const char *param);

//
int fmt_malware(ci_request_t *req, char *buf, int len, const char *param);


struct ci_fmt_entry GlobalTable [] = {
    { "%a", "Remote IP-Address", fmt_remoteip },
    {"%la", "Local IP Address", fmt_localip },
    {"%lp", "Local port", fmt_none},
    {"%>a", "Http Client IP Address", fmt_httpclientip},
    {"%<A", "Http Server IP Address", fmt_httpserverip},
    {"%ts", "Seconds since epoch", fmt_seconds},
    {"%tl", "Local time", fmt_localtime},
    {"%tg", "GMT time", fmt_gmttime},
    {"%tr", "Response time", fmt_none},
    {"%>hi", "Http request header", fmt_none},
    {"%>ho", "Modified Http request header", fmt_http_req_head_o},
    {"%huo", "Modified Http request url", fmt_http_req_url_o},
    {"%hu", "Http request url", fmt_none},
    {"%<hi", "Http reply header", fmt_none},
    {"%<ho", "Modified Http reply header", fmt_http_res_head_o},
    {"%Hs", "Http reply status", fmt_none},
    {"%Hso", "Modified Http reply status", fmt_none},

    {"%iu", "Icap request url", fmt_request},
    {"%im", "Icap method", fmt_icapmethod},
    {"%is", "Icap status code", fmt_icapstatus},
    {"%>ih", "Icap request header", fmt_icap_req_head},
    {"%<ih", "Icap response header", fmt_icap_res_head},
    {"%ipl", "Icap preview length", fmt_req_preview_len},

    {"%Ih", "Http bytes received", fmt_req_http_bytes_rcv},
    {"%Oh", "Http bytes sent", fmt_req_http_bytes_sent},
    {"%Ib", "Http body bytes received", fmt_req_body_bytes_rcv},
    {"%Ob", "Http body bytes sent", fmt_req_body_bytes_sent},

    {"%I", "Bytes received", fmt_req_bytes_rcv},
    {"%O", "Bytes sent", fmt_req_bytes_sent},

    {"%bph", "Body data preview", fmt_req_preview_hex},
    {"%un", "Username", fmt_username},
    {"%Sl", "Service log string", fmt_logstr},
    {"%Sa", "Attribute set by service", fmt_req_attribute},
    {"%%", "% sign", fmt_percent},

    // custom one just for the malware name
    {"%mn", "Malware Name", fmt_malware},
    { NULL, NULL, NULL}
};

#endif
