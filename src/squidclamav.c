/*
 *  Copyright (C) 2005-2019 Gilles Darold
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 *  Some part of the code of squidclamav are learn or simply copy/paste
 *  from the srv_clamav c-icap service written by Christos Tsantilas.
 *
 *  Copyright (C) 2004 Christos Tsantilas
 *
 * Thanks to him for his great work.
 */

/*
 libarchive support by Vieri Di Paola
 */

/*
 Fix conflicting types for `strnstr' on freeBSD
 between string.h and c_icap/util.h declaration
 */
#ifndef HAVE_STRNSTR
#define HAVE_STRNSTR 1
#endif

#include "c-icap.h"
#include "service.h"
#include "header.h"
#include "body.h"
#include "simple_api.h"
#include "debug.h"
#include "cfg_param.h"
#include "squidclamav.h"
#include "filetype.h"
#include "ci_threads.h"
#include "mem.h"
#include "commands.h"
#include "txtTemplate.h"
#include <errno.h>
#include <signal.h>

/* headers for libarchive support */
#ifdef HAVE_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif

/* Structure used to store information passed throught the module methods */
typedef struct av_req_data {
    ci_simple_file_t *body;
    ci_request_t *req;
    ci_membuf_t *error_page;
    int blocked;
    int no_more_scan;
    int virus;
    char *url;
    char *user;
    char *clientip;
    char *malware;
    char *recover;
} av_req_data_t;

static int SEND_PERCENT_BYTES = 0;
static ci_off_t START_SEND_AFTER = 1;

/*squidclamav service extra data ... */
ci_service_xdata_t *squidclamav_xdata = NULL;

int AVREQDATA_POOL = -1;

int squidclamav_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf);
int squidclamav_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t *);
int squidclamav_end_of_data_handler(ci_request_t *);
void *squidclamav_init_request_data(ci_request_t * req);
void squidclamav_close_service();
void squidclamav_release_request_data(void *data);
int squidclamav_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t * req);
int squidclamav_post_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf);

/* General functions */
void set_istag(ci_service_xdata_t * srv_xdata);
#ifdef HAVE_LIBARCHIVE
/* Functions for libarchive support */
const char *get_filename_ext(const char *filename);
int copy_file(int ptr_old, const char  *new_filename);
int has_invalid_chars(const char *inv_chars, const char *target);
#endif

/* Declare SquidClamav C-ICAP service */
CI_DECLARE_MOD_DATA ci_service_module_t service = {
    "squidclamav",                    /*Module name */
    "SquidClamav/Antivirus service", /* Module short description */
    ICAP_RESPMOD | ICAP_REQMOD,      /* Service type modification */
    squidclamav_init_service,          /* init_service. */
    squidclamav_post_init_service,     /* post_init_service. */
    squidclamav_close_service,         /* close_service */
    squidclamav_init_request_data,     /* init_request_data. */
    squidclamav_release_request_data,  /* release request data */
    squidclamav_check_preview_handler, /* Preview data */
    squidclamav_end_of_data_handler,   /* when all data has been received */
    squidclamav_io,
    NULL,
    NULL
};

int statit = 0;
int timeout = 1;
char *redirect_url = NULL;
char *clamd_local = NULL;
char *clamd_ip = NULL;
char *clamd_port = NULL;
char *clamd_curr_ip = NULL;
SCPattern *patterns = NULL;
int pattc = 0;
int current_pattern_size = 0;
ci_off_t maxsize = 0;
int logredir = 0;
int dnslookup = 1;
int safebrowsing = 0;
int multipart = 0;
ci_off_t banmaxsize = 0;
/* Default scan mode ScanAllExcept */
int scan_mode = 1;

#ifdef HAVE_LIBARCHIVE
/* vars for libarchive support */
int enable_libarchive = 0;
int banfile = 0;
char *recover_path = NULL;
int recovervirus = 1;
int ban_max_entries = 0;
int ban_max_matched_entries = 0;
#endif

/* Used by pipe to squidGuard */
int usepipe = 0;
pid_t pid;
FILE *sgfpw = NULL;
FILE *sgfpr = NULL;


/* --------------- URL CHECK --------------------------- */

struct http_info {
    char method[MAX_METHOD_SIZE];
    char url[MAX_URL];
};

int extract_http_info(ci_request_t *, ci_headers_list_t *, struct http_info *);
const char *http_content_type(ci_request_t *);
void free_global ();
void free_pipe ();
void generate_redirect_page(char *, ci_request_t *, av_req_data_t *);
void generate_response_page(ci_request_t *, av_req_data_t *);
#ifdef HAVE_CICAP_TEMPLATE
void generate_template_page(ci_request_t *, av_req_data_t *);
void cfgreload_command(const char *name, int type, const char **argv);
#else
void cfgreload_command(char *name, int type, char **argv);
#endif
int create_pipe(char *command);
int dconnect (void);
int connectINET(char *serverHost, uint16_t serverPort);
char * replace(const char *s, const char *old, const char *new);
int squidclamav_safebrowsing(ci_request_t * req, char *url, const char *clientip, const char *username);

/* ----------------------------------------------------- */

/* Sends bytes over a socket. Returns the number of bytes sent */
int sendln(int asockd, const char *line, unsigned int len)
{
    int bytesent = 0;
    while (len) {
        int sent = send(asockd, line, len, 0);
        if (sent <= 0) {
            if(sent && errno == EINTR) continue;
            debugs(0, "ERROR Can't send to clamd: %s\n", strerror(errno));
            return sent;
        }
        line += sent;
        len -= sent;
        bytesent += sent;
    }
    return bytesent;
}

int squidclamav_init_service(ci_service_xdata_t * srv_xdata,
                             struct ci_server_conf *server_conf)
{
    unsigned int xops;

    debugs(1, "DEBUG Going to initialize squidclamav\n");

    squidclamav_xdata = srv_xdata;
    set_istag(squidclamav_xdata);
    ci_service_set_preview(srv_xdata, 1024);
    ci_service_enable_204(srv_xdata);
    ci_service_set_transfer_preview(srv_xdata, "*");

    xops = CI_XCLIENTIP | CI_XSERVERIP;
    xops |= CI_XAUTHENTICATEDUSER | CI_XAUTHENTICATEDGROUPS;
    ci_service_set_xopts(srv_xdata, xops);

    /*Initialize object pools*/
    AVREQDATA_POOL = ci_object_pool_register("av_req_data_t", sizeof(av_req_data_t));

    if(AVREQDATA_POOL < 0) {
        debugs(0, "FATAL error registering object_pool av_req_data_t\n");
        return CI_ERROR;
    }

    /* Reload configuration command */
    register_command("squidclamav:cfgreload", MONITOR_PROC_CMD | CHILDS_PROC_CMD, cfgreload_command);


    /* allocate memory for some global variables */
    clamd_curr_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
    memset(clamd_curr_ip, 0, sizeof (char) * SMALL_CHAR);

    /*********************
      read config files
     ********************/
    if (load_patterns() == 0) {
        return CI_ERROR;
    }

    return CI_OK;
}

#ifdef HAVE_CICAP_TEMPLATE
void cfgreload_command(const char *name, int type, const char **argv)
#else
void cfgreload_command(char *name, int type, char **argv)
#endif
{
    debugs(0, "LOG reload configuration command received\n");

    free_global();
    statit = 0;

    pattc = 0;
    current_pattern_size = 0;
    maxsize = 0;
    logredir = 0;
    dnslookup = 1;
    safebrowsing = 0;
    multipart = 0;
    scan_mode = 1;

#ifdef HAVE_LIBARCHIVE
    /* libarchive */
    enable_libarchive = 0;
    banmaxsize = 0;
    recovervirus = 0;
    ban_max_entries = 0;
    ban_max_matched_entries = 0;
#endif

    /* reallocate memory for some global variables removed in free_global() */
    clamd_curr_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
    memset(clamd_curr_ip, 0, sizeof (char) * SMALL_CHAR);

    /* read configuration file */
    if (load_patterns() == 0)
        debugs(0, "FATAL reload configuration command failed!\n");
    if (squidclamav_xdata)
        set_istag(squidclamav_xdata);

}

int squidclamav_post_init_service(ci_service_xdata_t * srv_xdata,
                                  struct ci_server_conf *server_conf)
{
    return CI_OK;
}

void squidclamav_close_service()
{
    debugs(2, "DEBUG clean all memory!\n");
    free_global();
    ci_object_pool_unregister(AVREQDATA_POOL);
}

void *squidclamav_init_request_data(ci_request_t * req)
{
    av_req_data_t *data;

    debugs(2, "DEBUG initializing request data handler.\n");

    if (!(data = ci_object_pool_alloc(AVREQDATA_POOL))) {
        debugs(0, "FATAL Error allocation memory for service data!!!");
        return NULL;
    }
    data->body = NULL;
    data->url = NULL;
    data->clientip = NULL;
    data->user = NULL;
    data->malware = NULL;
    data->error_page = NULL;
    data->req = req;
    data->blocked = 0;
    data->no_more_scan = 0;
    data->virus = 0;
    data->recover = NULL;

    return data;
}


void squidclamav_release_request_data(void *data)
{

    if (data)
    {
        debugs(2, "DEBUG Releasing request data.\n");

        if (((av_req_data_t *) data)->body)
            ci_simple_file_destroy(((av_req_data_t *) data)->body);
        if (((av_req_data_t *) data)->url)
            ci_buffer_free(((av_req_data_t *) data)->url);
        if (((av_req_data_t *) data)->user)
            ci_buffer_free(((av_req_data_t *) data)->user);
        if (((av_req_data_t *) data)->clientip)
            ci_buffer_free(((av_req_data_t *) data)->clientip);
        if (((av_req_data_t *) data)->error_page)
            ci_membuf_free(((av_req_data_t *) data)->error_page);

        ci_object_pool_free(data);
    }
}

int squidclamav_check_preview_handler(char *preview_data, int preview_data_len,
                                      ci_request_t * req)
{
    ci_headers_list_t *req_header;
    struct http_info httpinf;
    av_req_data_t *data = ci_service_data(req);
    const char *clientip;
    struct hostent *clientname;
    unsigned long ip;
    const char *username;
    int chkipdone = 0;

    debugs(2, "DEBUG processing preview header.\n");

    if (preview_data_len) {
        debugs(2, "DEBUG preview data size is %d\n", preview_data_len);
    }

    /* Extract the HTTP header from the request */
    if ((req_header = ci_http_request_headers(req)) != NULL) {
	    int scanit = 0;
	    int content_length = 0;
	    const char *content_type = NULL;

	    /* Get the Authenticated user */
	    if ((username = ci_headers_value(req->request_header, "X-Authenticated-User")) != NULL) {
		debugs(2, "DEBUG X-Authenticated-User: %s\n", username);
		if (scan_mode == SCAN_ALL) {
		    /* if a TRUSTUSER match => no virus scan */
		    if (simple_pattern_compare(username, TRUSTUSER) == 1) {
		        debugs(2, "DEBUG No antivir check (TRUSTUSER match) for user: %s\n", username);
		        return CI_MOD_ALLOW204;
		    }
		} else {
		    /* if a UNTRUSTUSER match => virus scan */
		    if (simple_pattern_compare(username, UNTRUSTUSER) == 1) {
		        debugs(2, "DEBUG antivir check (UNTRUSTUSER match) for user: %s\n", username);
			scanit = 1;
		    }
		}
	    }

	    /* Check client Ip against SquidClamav trustclient */
	    if ((clientip = ci_headers_value(req->request_header, "X-Client-IP")) != NULL) {
		debugs(2, "DEBUG X-Client-IP: %s\n", clientip);
		ip = inet_addr(clientip);
		chkipdone = 0;
		if (dnslookup == 1) {
		    if ( (clientname = gethostbyaddr((char *)&ip, sizeof(ip), AF_INET)) != NULL) {
			if (clientname->h_name != NULL) {
		            if (scan_mode == SCAN_ALL) {
			        /* if a TRUSTCLIENT match => no virus scan */
			        if (client_pattern_compare(clientip, clientname->h_name) > 0) {
				    debugs(2, "DEBUG no antivir check (TRUSTCLIENT match) for client: %s(%s)\n", clientname->h_name, clientip);
				    return CI_MOD_ALLOW204;
			        }
			    } else {
			        /* if a UNTRUSTCLIENT match => virus scan */
			        if (client_pattern_compare(clientip, clientname->h_name) > 0) {
				    debugs(2, "DEBUG antivir check (UNTRUSTCLIENT match) for client: %s(%s)\n", clientname->h_name, clientip);
			            scanit = 1;
			        }
			    }
			    chkipdone = 1;
			}
		    }
		}
		if (chkipdone == 0) {
		    if (scan_mode == SCAN_ALL) {
		        /* if a TRUSTCLIENT match => no virus scan */
		        if (client_pattern_compare(clientip, NULL) > 0) {
			    debugs(2, "DEBUG No antivir check (TRUSTCLIENT match) for client: %s\n", clientip);
			    return CI_MOD_ALLOW204;
		        }
		    } else {
		        /* if a UNTRUSTCLIENT match => virus scan */
		        if (client_pattern_compare(clientip, NULL) > 0) {
			    debugs(2, "DEBUG antivir check (UNTRUSTCLIENT match) for client: %s\n", clientip);
			    scanit = 1;
		        }
		    }
		}
	    }

	    /* Get the requested URL */
	    if (!extract_http_info(req, req_header, &httpinf)) {
		/* Something wrong in the header or unknow method */
		debugs(1, "DEBUG bad http header, aborting.\n");
		return CI_MOD_ALLOW204;
	    }

	    debugs(2, "DEBUG URL requested: %s\n", httpinf.url);

	    /* CONNECT (https) and OPTIONS methods can not be scanned so abort */
	    if ( (strcmp(httpinf.method, "CONNECT") == 0) || (strcmp(httpinf.method, "OPTIONS") == 0) ) {
		debugs(2, "DEBUG method %s can't be scanned.\n", httpinf.method);
		return CI_MOD_ALLOW204;
	    }

	    if (scan_mode == SCAN_ALL) {
	        /* Check the URL against SquidClamav whitelist/abort entries */
	        if ( simple_pattern_compare(httpinf.url, WHITELIST) == 1
			|| simple_pattern_compare(httpinf.url, ABORT) == 1 ) {
		    debugs(2, "DEBUG No antivir check (WHITELIST/ABORT match) for url: %s\n", httpinf.url);
		    return CI_MOD_ALLOW204;
	        }
	    } else {
	        /* Check the URL against SquidClamav blacklist/scan entries */
	        if ( simple_pattern_compare(httpinf.url, BLACKLIST) == 1
	        	|| simple_pattern_compare(httpinf.url, SCAN) == 1 ) {
		    debugs(2, "DEBUG antivir check (BLACKLIST/SCAN match) for url: %s\n", httpinf.url);
		    scanit = 1;
	        }
	    }

	    /* set null client username to - */
	    if (username == NULL) {
		username = (char *)malloc(sizeof(char)*2);
		strcpy((char *)username, "-");
	    }

	    /* set null client ip to - */
	    if (clientip == NULL) {
		clientip = (char *)malloc(sizeof(char)*2);
		strcpy((char *)clientip, "-");
		debugs(0, "ERROR clientip is null, you must set 'icap_send_client_ip on' into squid.conf\n");
	    }

	    if (safebrowsing == 1) {
		if (squidclamav_safebrowsing(req, httpinf.url, clientip, username) != 0) {
		    debugs(1, "DEBUG Malware found stopping here.\n");
		    return CI_MOD_CONTINUE;
		}
	    }

	    /* Get the content type header */
	    if ((content_type = http_content_type(req)) != NULL) {
                while(*content_type == ' ' || *content_type == '\t') content_type++;
		debugs(2, "DEBUG Content-Type: %s\n", content_type);
		if (scan_mode == SCAN_ALL) {
		    /* Check the Content-Type against SquidClamav abortcontent */
		    if (simple_pattern_compare(content_type, ABORTCONTENT)) {
		        debugs(2, "DEBUG No antivir check (ABORTCONTENT match) for content-type: %s\n", content_type);
		        return CI_MOD_ALLOW204;
		    }
		} else {
		    /* Check the Content-Type against SquidClamav scancontent */
		    if (simple_pattern_compare(content_type, SCANCONTENT)) {
		        debugs(2, "DEBUG No antivir check (SCANCONTENT match) for content-type: %s\n", content_type);
		        scanit = 1;
		    }
		}
	    }

	    /* In ScanNothingExcept mode get out if we have not detected something to scan */
	    if (scan_mode == SCAN_NONE && scanit == 0) {
	        return CI_MOD_ALLOW204;
	    }

	    /* Get the content length header */
	    content_length = ci_http_content_length(req);
	    if ((content_length > 0) && (maxsize > 0) && (content_length >= maxsize)) {
		debugs(2, "DEBUG No antivir check, content-length upper than maxsize (%" PRINTF_OFF_T " > %d)\n", (CAST_OFF_T) content_length, (int) maxsize);
		return CI_MOD_ALLOW204;
	    }

	    /* No data, so nothing to scan */
	    if (!data || !ci_req_hasbody(req)) {
		debugs(2, "DEBUG No body data, allow 204\n");
		return CI_MOD_ALLOW204;
	    }

	    data->url = ci_buffer_alloc(strlen(httpinf.url)+1);
	    strcpy(data->url, httpinf.url);

	    data->user = ci_buffer_alloc(strlen(username)+1);
	    strcpy(data->user, username);

	    data->clientip = ci_buffer_alloc(strlen(clientip)+1);
	    strcpy(data->clientip, clientip);
 
    } else {

	debugs(1, "WARNING bad http header, can not check URL, Content-Type and Content-Length.\n");
	/* No data, so nothing to scan */
	if (!data || !ci_req_hasbody(req)) {
	    debugs(1, "DEBUG No body data, allow 204\n");
	    return CI_MOD_ALLOW204;
	}

    }

    if (preview_data_len == 0) {
	debugs(2, "DEBUG Can not begin to scan url: No preview data.\n");
    }

    data->body = ci_simple_file_new(0);
    if ((SEND_PERCENT_BYTES >= 0) && (START_SEND_AFTER == 0)) {
        ci_req_unlock_data(req);
        ci_simple_file_lock_all(data->body);
    }
    if (!data->body)
        return CI_ERROR;

    if (preview_data_len) {
        if (ci_simple_file_write(data->body, preview_data, preview_data_len, ci_req_hasalldata(req)) == CI_ERROR)
            return CI_ERROR;
    }

    debugs(2, "DEBUG End of method squidclamav_check_preview_handler\n");

    return CI_MOD_CONTINUE;
}

int squidclamav_read_from_net(char *buf, int len, int iseof, ci_request_t * req)
{
    av_req_data_t *data = ci_service_data(req);
    int allow_transfer;

    if (!data)
        return CI_ERROR;

    if (!data->body)
        return len;

    if (data->no_more_scan == 1) {
        return ci_simple_file_write(data->body, buf, len, iseof);
    }

    if ((maxsize > 0) && (data->body->bytes_in >= maxsize)) {
        data->no_more_scan = 1;
        ci_req_unlock_data(req);
        ci_simple_file_unlock_all(data->body);
        debugs(1, "DEBUG No more antivir check, downloaded stream is upper than maxsize (%d>%d)\n", (int)data->body->bytes_in, (int)maxsize);
    } else if (SEND_PERCENT_BYTES && (START_SEND_AFTER < data->body->bytes_in)) {
        ci_req_unlock_data(req);
        allow_transfer = (SEND_PERCENT_BYTES * (data->body->endpos + len)) / 100;
        ci_simple_file_unlock(data->body, allow_transfer);
    }

    return ci_simple_file_write(data->body, buf, len, iseof);
}

int squidclamav_write_to_net(char *buf, int len, ci_request_t * req)
{
    int bytes;
    av_req_data_t *data = ci_service_data(req);

    if (!data)
        return CI_ERROR;

    if (data->blocked == 1 && data->error_page == 0) {
        debugs(2, "DEBUG ending here, content was blocked\n");
        return CI_EOF;
    }
    if (data->virus == 1 && data->error_page == 0) {
        debugs(2, "DEBUG ending here, virus was found\n");
        return CI_EOF;
    }

    /* if a virus was found or the page has been blocked, a warning page
       has already been generated */
    if (data->error_page)
        return ci_membuf_read(data->error_page, buf, len);

    if (data->body)
        bytes = ci_simple_file_read(data->body, buf, len);
    else
        bytes =0;

    return bytes;
}

int squidclamav_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                   ci_request_t * req)
{

    if (rbuf && rlen) {
        *rlen = squidclamav_read_from_net(rbuf, *rlen, iseof, req);
        if (*rlen == CI_ERROR)
            return CI_ERROR;
        else if (*rlen < 0)
            return CI_OK;
    } else if (iseof) {
        if (squidclamav_read_from_net(NULL, 0, iseof, req) == CI_ERROR)
            return CI_ERROR;
    }

    if (wbuf && wlen) {
        *wlen = squidclamav_write_to_net(wbuf, *wlen, req);
    }

    return CI_OK;
}

int squidclamav_end_of_data_handler(ci_request_t * req)
{
    av_req_data_t *data = ci_service_data(req);
    ci_simple_file_t *body;
    char cbuff[LBUFSIZ];
    char clbuf[SMALL_BUFF];
    const char *content_type = NULL;

    ssize_t ret;
    int nbread = 0;
    int sockd;
    unsigned long total_read;

#ifdef HAVE_LIBARCHIVE
    int content_length = 0;
    /* If local path was specified then generate unique file name to copy data.
    It can be used to put banned files and viri in quarantine directory. */
    char bfileref[SMALL_BUFF];
#endif

    debugs(2, "DEBUG ending request data handler.\n");

    /* Nothing more to scan */
    if (!data || !data->body)
        return CI_MOD_DONE;

    if (data->blocked == 1) {
        debugs(1, "DEBUG blocked content, sending redirection header / error page.\n");
        return CI_MOD_DONE;
    }

    body = data->body;
    if (data->no_more_scan == 1) {
        debugs(1, "DEBUG no more data to scan, sending content.\n");
        ci_simple_file_unlock_all(body);
        return CI_MOD_DONE;
    }

    /* SCAN DATA HERE */

#ifdef HAVE_LIBARCHIVE
    /* Block archive entries supported by libarchive before scanning for virus. */

    /* Get content length*/
    content_length = ci_http_content_length(req);

    if (enable_libarchive > 0 && (banfile == 1) && (content_length > 0) && (content_length <= banmaxsize)) {

        struct archive *a;
        struct archive_entry *entry;
        int r;
        int archive_entries = 0;
        int matched_archive_entries = 0;
        char descr[SMALL_BUFF];

        lseek(body->fd, 0, SEEK_SET);

        a = archive_read_new();
        archive_read_support_filter_all(a);
        archive_read_support_format_all(a);
        r = archive_read_open_fd(a, body->fd, 10240);
        if (r != ARCHIVE_OK) {
            debugs(2, "WARNING libarchive could not open file descriptor (%d).\n", r);
        } else {
            debugs(2, "DEBUG scanning for archives supported by libarchive (content-length [%" PRINTF_OFF_T "] <= max size [%d])\n", (CAST_OFF_T) content_length, (int) banmaxsize);
            while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
                archive_entries++;
                debugs(3, "LOG libarchive processing entry %d => %s\n", archive_entries, archive_entry_pathname(entry));
                if (simple_pattern_compare(archive_entry_pathname(entry), BANFILE)) {
                    matched_archive_entries++;
                    data->virus = 1;
                    debugs(0, "LOG libarchive entry %d matched [%s]\n", archive_entries, archive_entry_pathname(entry));
                    /* inform user why this file was banned */
                    snprintf(descr, sizeof(descr), "BANNED:%s", archive_entry_pathname(entry));
		    data->malware = ci_buffer_alloc(strlen(descr)+1);
		    strcpy(data->malware, descr);
                    if ((ban_max_entries == 0) && (ban_max_matched_entries == 0)) {
                        break;
                    }
                }
                if (((ban_max_entries > 0) && (archive_entries > ban_max_entries)) || ((ban_max_matched_entries > 0) && (matched_archive_entries > ban_max_matched_entries))) {
                    break;
                }
            }
            r = archive_read_free(a);
            if (r != ARCHIVE_OK) {
                debugs(2, "WARNING could not close file descriptor\n");
            }
        }
        /* check number of entries */
        if ((data->virus) && (((ban_max_entries > 0) && (archive_entries > ban_max_entries)) || ((ban_max_matched_entries > 0) && (matched_archive_entries > ban_max_matched_entries)))) {
            data->virus = 0;
        }
        if (data->virus) {
            if (recover_path != NULL) {
                /* try to generate unique file name */
                srand(time(NULL));
                /*
		 * Avoid char problems in original file name and improve
		 * admin searchability by setting file name format to
		 * web_USER_CLIENTIP_UNIXTIME_RAND(0-99).FILEEXT
		 */
                if (has_invalid_chars(INVALID_CHARS, get_filename_ext(data->url)) == 1) {
                    debugs(3, "DEBUG libarchive setting up file name without extension.\n");
                    snprintf(bfileref, sizeof(bfileref), "%s%s_%s_%d_%d", PREFIX_BANNED, data->user, data->clientip, (int)time(NULL), (int)rand() % 99);
                } else {
                    debugs(3, "DEBUG libarchive setting up file name with extension.\n");
                    snprintf(bfileref, sizeof(bfileref), "%s%s_%s_%d_%d.%s", PREFIX_BANNED, data->user, data->clientip, (int)time(NULL), (int)rand() % 99, get_filename_ext(data->url));
                }
                debugs(2, "DEBUG libarchive recover file [%s]\n", bfileref);
                /* copy file to quarantine dir */
                lseek(body->fd, 0, SEEK_SET);
                char targetf[MAX_URL];
                snprintf(targetf, sizeof(targetf), "%s/%s", recover_path, bfileref);
                debugs(0, "LOG libarchive match found, sending redirection header / error page. Copied to [%s] with exit code [%d].\n", targetf, copy_file(body->fd, targetf));
		data->recover = ci_buffer_alloc(strlen(bfileref)+1);
		strcpy(data->recover, bfileref);
                if (!ci_req_sent_data(req)) {
                    generate_response_page(req, data);
                }
            } else {
                debugs(0, "LOG libarchive match found, sending redirection header / error page. Data not copied.\n");
            }
            return CI_MOD_DONE;
        }
    } else if (enable_libarchive > 0 && content_length > 0) {
        debugs(2, "DEBUG libarchive no archive check, content-length bigger than maxsize (%" PRINTF_OFF_T " > %d)\n", (CAST_OFF_T) content_length, (int) banmaxsize);
    }

    /* Now check for virus. */
    if ( enable_libarchive == 0 || ( (content_length > 0) && (maxsize >= 0) && (content_length <= maxsize) ) ) {
#endif

    if ((sockd = dconnect ()) < 0) {
        debugs(0, "ERROR Can't connect to Clamd daemon.\n");
        return CI_MOD_ERROR;
    }
    debugs(2, "DEBUG Sending zINSTREAM command to clamd.\n");

    if (write(sockd, "zINSTREAM", 10) <= 0) {
        debugs(0, "ERROR Can't write to Clamd socket.\n");
        close(sockd);
        return CI_MOD_ERROR;
    }

    debugs(2, "DEBUG Ok connected to clamd.\n");

    /* Check the Content-Type is of type multipart */
    if (multipart == 1 && ((content_type = http_content_type(req)) != NULL)) {
	while(*content_type == ' ' || *content_type == '\t') content_type++;
	debugs(2, "DEBUG Content-Type: %s\n", content_type);
        if (strncmp(content_type, "multipart/", 10) == 0) {
            int len = strlen(content_type);
            debugs(2, "DEBUG Found multipart Content-Type: %s\n", content_type);
            if (len > (LBUFSIZ - sizeof(uint32_t) - 30)) {
                debugs(0, "ERROR Can't write multipart header to clamd socket: header too big.\n");
            } else {
                uint32_t buf[LBUFSIZ/sizeof(uint32_t)];
                int header_size = len + 30;
                buf[0] = htonl(header_size);
                memset(cbuff, 0, sizeof(cbuff));
		snprintf(cbuff, header_size, "To: ClamAV\r\nContent-Type: %s\r\n\r\n", content_type);
		memcpy(&buf[1],(const char*) cbuff, header_size);
                ret = sendln (sockd,(const char *) buf, header_size + sizeof(uint32_t));
                if ( ret <= 0 ) {
                    debugs(0, "ERROR Can't write multipart headers to clamd socket.\n");
                }
            }
        }
    }

    /*-----------------------------------------------------*/

    debugs(2, "DEBUG Scanning data now\n");
    lseek(body->fd, 0, SEEK_SET);
    memset(cbuff, 0, sizeof(cbuff));
    total_read = 0;
    while (data->virus == 0 && (nbread = read(body->fd, cbuff, BUFSIZ)) > 0) {
        uint32_t buf[LBUFSIZ/sizeof(uint32_t)];
        buf[0] = htonl(nbread);
        memcpy(&buf[1],(const char*) cbuff, nbread);
        total_read += nbread;
        ret = sendln (sockd,(const char *) buf, nbread+sizeof(uint32_t));
        if ( (ret <= 0) && (total_read > 0) ) {
            debugs(3, "ERROR Can't write to clamd socket (maybe we reach clamd StreamMaxLength, total read: %ld).\n", total_read);
            break;
        } else if ( ret <= 0 ) {
            debugs(0, "ERROR Can't write to clamd socket.\n");
            break;
        } else {
            debugs(3, "DEBUG Write %d bytes on %d to socket\n", (int)ret, nbread);
            /*debugs(3, "DEBUG sent: %s\n", cbuff);*/
        }
        memset(cbuff, 0, sizeof(cbuff));
    }

    uint32_t buf[LBUFSIZ/sizeof(uint32_t)];
    *buf = 0;
    ret = sendln (sockd,(const char *) buf, 4);
    if (ret <= 0)
    {
        debugs(0, "ERROR Can't write zINSTREAM ending chars to clamd socket.\n");
    } else {

        /* Reading clamd result */
        memset (clbuf, 0, sizeof(clbuf));
        while ((nbread = read(sockd, clbuf, SMALL_BUFF - 1)) > 0) {
	    clbuf[nbread] = '\0';
            debugs(2, "DEBUG received from Clamd: %s\n", clbuf);
            if (strstr (clbuf, "FOUND")) {
                data->virus = 1;
		data->malware = ci_buffer_alloc(strlen(clbuf)+1);
		strcpy(data->malware, clbuf);
                debugs(0, "LOG Virus found in %s ending download [%s]\n", data->url, clbuf);
#ifdef HAVE_LIBARCHIVE
                /* do as for banned files (libarchive) */
                if (enable_libarchive > 0 && (recovervirus == 1) && (recover_path != NULL)) {
                    /* Change prefix of unique data file so it can be identified as a virus. */
                    srand(time(NULL));
                    /* Avoid char problems in original file name and improve admin searchability by setting file name format to web_USER_CLIENTIP_UNIXTIME_RAND(0-99).FILEEXT */
                    if (has_invalid_chars(INVALID_CHARS, get_filename_ext(data->url)) == 1) {
                        snprintf(bfileref, sizeof(bfileref), "%s%s_%s_%d_%d", PREFIX_VIRUS, data->user, data->clientip, (int)time(NULL), (int)rand() % 99);
                    } else {
                        snprintf(bfileref, sizeof(bfileref), "%s%s_%s_%d_%d.%s", PREFIX_VIRUS, data->user, data->clientip, (int)time(NULL), (int)rand() % 99, get_filename_ext(data->url));
                    }
		    data->recover = ci_buffer_alloc(strlen(bfileref)+1);
		    strcpy(data->recover, bfileref);
                    debugs(0, "LOG libarchive recover file [%s]\n", bfileref);
                }
#endif
                if (!ci_req_sent_data(req)) {
                    generate_response_page(req, data);
                }
                break;
            }
            memset(clbuf, 0, sizeof(clbuf));
        }
    }

    /* close second socket to clamd */
    if (sockd > -1) {
        debugs(2, "DEBUG Closing Clamd connection.\n");
        close(sockd);
    }

    if (data->virus) {
#ifdef HAVE_LIBARCHIVE
        /* Copy viri just like banned files (libarchive) if requested by user. */
	if (enable_libarchive > 0) {
            if ((recovervirus == 1) && (recover_path != NULL)) {
                lseek(body->fd, 0, SEEK_SET);
                char targetf[MAX_URL];
                snprintf(targetf, sizeof(targetf), "%s/%s", recover_path, bfileref);
                debugs(0, "LOG Virus found, sending redirection header / error page. Copied to [%s] with exit code [%d].\n", targetf, copy_file(body->fd, targetf));
            } else {
                debugs(0, "LOG Virus found, sending redirection header / error page.\n");
            }
	}
#else
	debugs(1, "LOG Virus found, sending redirection header / error page.\n");
#endif
        return CI_MOD_DONE;
    }

#ifdef HAVE_LIBARCHIVE
    } else if (enable_libarchive > 0 && content_length > 0) { /* Checked for virus. */
        debugs(2, "DEBUG No virus check, content-length bigger than maxsize (%" PRINTF_OFF_T " > %d)\n", (CAST_OFF_T) content_length, (int) maxsize);
    }
#endif

    if (!ci_req_sent_data(req) && ci_req_allow204(req)) {
        debugs(2, "DEBUG Responding with allow 204\n");
        return CI_MOD_ALLOW204;
    }

    debugs(3, "DEBUG unlocking data to be sent.\n");
    ci_simple_file_unlock_all(body);

    return CI_MOD_DONE;
}

void set_istag(ci_service_xdata_t * srv_xdata)
{
    char istag[SERVICE_ISTAG_SIZE + 1];


    snprintf(istag, SERVICE_ISTAG_SIZE, "-%d-%s-%d%d",1, "squidclamav", 1, 0);
    istag[SERVICE_ISTAG_SIZE] = '\0';
    ci_service_set_istag(srv_xdata, istag);
    debugs(2, "DEBUG setting istag to %s\n", istag);
}

/* util.c */

/* NUL-terminated version of strncpy() */
void xstrncpy (char *dest, const char *src, size_t n)
{
    if ( (src == NULL) || (strcmp(src, "") == 0))
        return;
    strncpy(dest, src, n-1);
    dest[n-1] = 0;
}

/* Emulate the Perl chomp() method: remove \r and \n from end of string */
void chomp (char *str)
{
    size_t len = 0;

    if (str == NULL) return;
    len = strlen(str);
    if ((len > 0) && str[len - 1] == 10) {
        str[len - 1] = 0;
        len--;
    }
    if ((len > 0) && str[len - 1] == 13)
        str[len - 1] = 0;

    return;
}

/* return 0 if path exists, -1 otherwise */
int isPathExists(const char *path)
{
    struct stat sb;

    if ( (path == NULL) || (strcmp(path, "") == 0) ) return -1;

    if (lstat(path, &sb) != 0) {
        return -1;
    }

    return 0;
}


/* return 0 if path is secure, -1 otherwise */
int isPathSecure(const char *path)
{
    struct stat sb;

    /* no path => unreal, that's possible ! */
    if (path == NULL) return -1;

    /* file doesn't exist or access denied = secure */
    /* fopen will fail */
    if (lstat(path, &sb) != 0) return 0;

    /* File is not a regular file => unsecure */
    if ( S_ISLNK(sb.st_mode ) ) return -1;
    if ( S_ISDIR(sb.st_mode ) ) return -1;
    if ( S_ISCHR(sb.st_mode ) ) return -1;
    if ( S_ISBLK(sb.st_mode ) ) return -1;
    if ( S_ISFIFO(sb.st_mode ) ) return -1;
    if ( S_ISSOCK(sb.st_mode ) ) return -1;

    return 0;
}

/* return 0 if file exists and is readable, -1 otherwise */
int
isFileExists(const char *path)
{
    struct stat sb;

    /* no path => unreal, that's possible ! */
    if (path == NULL) return -1;

    /* file doesn't exist or access denied */
    if (lstat(path, &sb) != 0) return -1;

    /* File is not a regular file */
    if ( S_ISDIR(sb.st_mode ) ) return -1;
    if ( S_ISCHR(sb.st_mode ) ) return -1;
    if ( S_ISBLK(sb.st_mode ) ) return -1;
    if ( S_ISFIFO(sb.st_mode ) ) return -1;
    if ( S_ISSOCK(sb.st_mode ) ) return -1;

    return 0;
}


/* Remove spaces and tabs from beginning and end of a string */
void trim(char *str)
{
    int i = 0;
    int j = 0;

    /* Remove spaces and tabs from beginning */
    while ( (str[i] == ' ') || (str[i] == '\t') ) {
        i++;
    }
    if (i > 0) {
        for (j = i; j < strlen(str); j++) {
            str[j-i] = str[j];
        }
        str[j-i] = '\0';
    }

    /* Now remove spaces and tabs from end */
    i = strlen(str) - 1;
    while ( (str[i] == ' ') || (str[i] == '\t')) {
        i--;
    }
    if ( i < (strlen(str) - 1) ) {
        str[i+1] = '\0';
    }
}

/* Try to emulate the Perl split() method: str is splitted on the
   all occurence of delim. Take care that empty fields are not returned */
char** split( char* str, const char* delim)
{
    int size = 0;
    char** splitted = NULL;
    char *tmp = NULL;
    tmp = strtok(str, delim);
    while (tmp != NULL) {
        splitted = (char**) realloc(splitted, sizeof(char**) * (size+1));
        if (splitted != NULL) {
            splitted[size] = tmp;
        } else {
            return(NULL);
        }
        tmp = strtok(NULL, delim);
        size++;
    }
    free(tmp);
    tmp = NULL;
    /* add null at end of array to help ptrarray_length */
    splitted = (char**) realloc(splitted, sizeof(char**) * (size+1));
    if (splitted != NULL) {
        splitted[size] = NULL;
    } else {
        return(NULL);
    }

    return splitted;
}

/* Return the length of a pointer array. Must be ended by NULL */
int ptrarray_length(char** arr)
{
    int i = 0;
    while(arr[i] != NULL) i++;
    return i;
}

void * xmallox (size_t len)
{
    void *memres = malloc (len);
    if (memres == NULL) {
        fprintf(stderr, "Running Out of Memory!!!\n");
        exit(EXIT_FAILURE);
    }
    return memres;
}

size_t xstrnlen(const char *s, size_t n)
{
    const char *p = (const char *)memchr(s, 0, n);
    return(p ? p-s : n);
}


/* pattern.c */

int isIpAddress(char *src_addr)
{
    char *ptr;
    int address;
    int i;
    char *s = (char *) malloc (sizeof (char) * LOW_CHAR);

    xstrncpy(s, src_addr, LOW_CHAR);

    /* make sure we have numbers and dots only! */
    if(strspn(s, "0123456789.") != strlen(s)) {
        free(s);
        return 1;
    }

    /* split up each number from string */
    ptr = strtok(s, ".");
    if(ptr == NULL) {
        free(s);
        return 1;
    }
    address = atoi(ptr);
    if(address < 0 || address > 255) {
        free(s);
        free(ptr);
        return 1;
    }

    for(i = 2; i < 4; i++) {
        ptr = strtok(NULL, ".");
        if (ptr == NULL) {
            free(s);
            return 1;
        }
        address = atoi(ptr);
        if (address < 0 || address > 255) {
            free(ptr);
            free(s);
            return 1;
        }
    }
    free(s);

    return 0;
}


int simple_pattern_compare(const char *str, const int type)
{
    int i = 0;

    /* pass througth all regex pattern */
    for (i = 0; i < pattc; i++)
    {
        if ( (patterns[i].type == type) && (regexec(&patterns[i].regexv, str, 0, 0, 0) == 0) )
	{
            switch(type)
	    {
                /* return 1 if string matches whitelist/abort pattern */
                case ABORT:
                    debugs(2, "DEBUG abort (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
                case WHITELIST:
                    debugs(2, "DEBUG whitelist (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
                /* return 1 if string matches blacklist/scan pattern */
                case SCAN:
                    debugs(2, "DEBUG scan (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
                case BLACKLIST:
                    debugs(2, "DEBUG blacklist (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
                /* return 1 if string matches trustuser pattern */
                case TRUSTUSER:
                     debugs(2, "DEBUG trustuser (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
                /* return 1 if string matches untrustuser pattern */
                case UNTRUSTUSER:
                    debugs(2, "DEBUG untrustuser (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
                /* return 1 if string matches abortcontent pattern */
                case ABORTCONTENT:
                    debugs(2, "DEBUG abortcontent (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
                /* return 1 if string matches scancontent pattern */
                case SCANCONTENT:
                    debugs(2, "DEBUG scancontent (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
#ifdef HAVE_LIBARCHIVE
                /* return 1 if string matches banfile pattern (libarchive) */
                case BANFILE:
                    debugs(2, "DEBUG banfile (%s) matched: %s\n", patterns[i].pattern, str);
                    return 1;
#endif
                default:
                    debugs(0, "ERROR unknown pattern match type: %s\n", str);
                    return -1;
	    }
        }
    }

    /* return 0 otherwise */
    return 0;
}

int client_pattern_compare(const char *ip, char *name)
{
    int i = 0;

    /* pass througth all regex pattern */
    for (i = 0; i < pattc; i++)
    {
        if ( (scan_mode == SCAN_ALL) && (patterns[i].type == TRUSTCLIENT) )
	{
            /* Look at client ip pattern matching */
            /* return 1 if string matches ip TRUSTCLIENT pattern */
            if (regexec(&patterns[i].regexv, ip, 0, 0, 0) == 0)
	    {
                debugs(2, "DEBUG trustclient (%s) matched: %s\n", patterns[i].pattern, ip);
                return 1;
            }
            /* Look at client name pattern matching */
            /* return 2 if string matches fqdn TRUSTCLIENT pattern */
	    else if ((name != NULL) && (regexec(&patterns[i].regexv, name, 0, 0, 0) == 0))
	    {
                debugs(2, "DEBUG trustclient (%s) matched: %s\n", patterns[i].pattern, name);
                return 2;
            }
        }
	else if ( (scan_mode == SCAN_NONE) && (patterns[i].type == UNTRUSTCLIENT) )
	{
            /* Look at client ip pattern matching */
            /* return 1 if string doesn't matches ip UNTRUSTCLIENT pattern */
            if (regexec(&patterns[i].regexv, ip, 0, 0, 0) != 0)
	    {
                debugs(3, "DEBUG untrustclient (%s) not matched: %s\n", patterns[i].pattern, ip);
                return 1;
            }
            /* Look at client name pattern matching */
            /* return 2 if string doesn't matches fqdn UNTRUSTCLIENT pattern */
	    else if ((name != NULL) && (regexec(&patterns[i].regexv, name, 0, 0, 0) != 0))
	    {
                debugs(3, "DEBUG untrustclient (%s) not matched: %s\n", patterns[i].pattern, name);
                return 2;
            }
	}
    }

    /* return 0 otherwise */
    return 0;
}

/* scconfig.c */

/* load the squidclamav.conf */
int load_patterns()
{
    char *buf = NULL;
    FILE *fp  = NULL;
    int ret   = 0;

    if (isPathExists(CONFIGDIR "/" CONFIG_FILE) == 0) {
        fp = fopen(CONFIGDIR "/" CONFIG_FILE, "rt");
        debugs(0, "LOG Reading configuration from %s\n", CONFIGDIR "/" CONFIG_FILE);
    }


    if (fp == NULL) {
        debugs(0, "FATAL unable to open configuration file: %s\n", CONFIGDIR "/" CONFIG_FILE);
        return 0;
    }

    buf = (char *)malloc(sizeof(char)*LOW_BUFF*2);
    if (buf == NULL) {
        debugs(0, "FATAL unable to allocate memory in load_patterns()\n");
        fclose(fp);
        return 0;
    }
    while ((fgets(buf, LOW_BUFF, fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        /* add to regex patterns array */
        if ( (strlen(buf) > 0) && (add_pattern(buf, 0) == 0) ) {
	    debugs(0, "FATAL can't add pattern: %s\n", buf);
            free(buf);
            fclose(fp);
            return 0;
        }
    }
    free(buf);
    ret = fclose(fp);
    if (ret != 0) {
        debugs(0, "ERROR Can't close configuration file (%d)\n", ret);
    }

    /* Set default values */
    if (clamd_local == NULL) {
        if (clamd_ip == NULL) {
            clamd_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
            if(clamd_ip == NULL) {
                debugs(0, "FATAL unable to allocate memory in load_patterns()\n");
                return 0;
            }
            xstrncpy(clamd_ip, CLAMD_SERVER, SMALL_CHAR);
        }

        if (clamd_port == NULL) {
            clamd_port = (char *) malloc (sizeof (char) * LOW_CHAR);
            if(clamd_port == NULL) {
                debugs(0, "FATAL unable to allocate memory in load_patterns()\n");
                return 0;
            }
            xstrncpy(clamd_port, CLAMD_PORT, LOW_CHAR);
        }
    }

#ifndef HAVE_CICAP_TEMPLATE
    if (redirect_url == NULL) {
	debugs(0, "FATAL you must set redirect_url or use c-icap 0.2.x or upper to use templates\n");
	return 0;
    }
#endif

    return 1;
}

int growPatternArray(SCPattern item)
{
    void *_tmp = NULL;
    if (pattc == current_pattern_size) {
        if (current_pattern_size == 0)
            current_pattern_size = PATTERN_ARR_SIZE;
        else
            current_pattern_size += PATTERN_ARR_SIZE;

        _tmp = realloc(patterns, (current_pattern_size * sizeof(SCPattern)));
        if (!_tmp) {
            return(-1);
        }

        patterns = (SCPattern*)_tmp;
    }
    patterns[pattc] = item;
    pattc++;

    return(pattc);
}

/* Add regexp expression to patterns array */
int add_pattern(char *s, int level)
{
    char *first = NULL;
    char *type  = NULL;
    int stored = 0;
    int regex_flags = REG_NOSUB;
    SCPattern currItem;
    char *end = NULL;

    /* skip empty and commented lines */
    if ( (xstrnlen(s, LOW_BUFF) == 0) || (strncmp(s, "#", 1) == 0)) return 1;

    /* Config file directives are construct as follow: name value */
    type = (char *)malloc(sizeof(char)*LOW_CHAR);
    first = (char *)malloc(sizeof(char)*LOW_BUFF);
    stored = sscanf(s, "%31s %255[^#]", type, first);

    if (stored < 2) {
        debugs(0, "FATAL Bad configuration line for [%s]\n", s);
        free(type);
        free(first);
        return 0;
    }
    /* remove extra space or tabulation */
    trim(first);

    debugs(0, "LOG Reading directive %s with value %s\n", type, first);
    /* URl to redirect Squid on virus found */
    if(strcmp(type, "redirect") == 0) {
        redirect_url = (char *) malloc (sizeof (char) * LOW_BUFF);
        if(redirect_url == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            xstrncpy(redirect_url, first, LOW_BUFF);
        }
        free(type);
        free(first);
        return 1;
    }

#ifdef HAVE_LIBARCHIVE

    /* Enable/disable libarchive support */
    if(strcmp(type, "enable_libarchive") == 0) {
        enable_libarchive = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    /* Path for banned file recovery (libarchive support) */
    if(strcmp(type, "recoverpath") == 0) {
        recover_path = (char *) malloc (sizeof (char) * LOW_BUFF);
        if(recover_path == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            if (isPathExists(first) == 0) {
                xstrncpy(recover_path, first, LOW_BUFF);
            } else {
                debugs(0, "LOG Wrong path to recoverpath, disabling.\n");
		free(recover_path);
            }
        }
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "recovervirus") == 0) {
        if (recovervirus == 1)
            recovervirus = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "ban_max_entries") == 0) {
        ban_max_entries = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "ban_max_matched_entries") == 0) {
        ban_max_matched_entries = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    /* banmaxsize requires previously set maxsize (libarchive support) */
    if (strcmp(type, "banmaxsize") == 0) {
        banmaxsize = ci_strto_off_t(first, &end, 10);
        if ((banmaxsize == 0 && errno != 0) || banmaxsize < 0)
            banmaxsize = 0;
        if (*end == 'k' || *end == 'K')
            banmaxsize = banmaxsize * 1024;
        else if (*end == 'm' || *end == 'M')
            banmaxsize = banmaxsize * 1024 * 1024;
        else if (*end == 'g' || *end == 'G')
            banmaxsize = banmaxsize * 1024 * 1024 * 1024;
        maxsize = max(maxsize, banmaxsize);
        free(type);
        free(first);
        return 1;
    }

#endif

    if(strcmp(type, "logredir") == 0) {
        if (logredir == 0)
            logredir = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "dnslookup") == 0) {
        if (dnslookup == 1)
            dnslookup = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "safebrowsing") == 0) {
        if (safebrowsing == 0)
            safebrowsing = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "multipart") == 0) {
        if (multipart == 0)
            multipart = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "timeout") == 0) {
        timeout = atoi(first);
        if (timeout > 10)
            timeout = 10;
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "stat") == 0) {
        statit = atoi(first);
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "clamd_ip") == 0) {
        clamd_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
        if (clamd_ip == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            xstrncpy(clamd_ip, first, SMALL_CHAR);
        }
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "clamd_port") == 0) {
        clamd_port = (char *) malloc (sizeof (char) * LOW_CHAR);
        if(clamd_port == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            xstrncpy(clamd_port, first, LOW_CHAR);
        }
        free(type);
        free(first);
        return 1;
    }

    if(strcmp(type, "clamd_local") == 0) {
        clamd_local = (char *) malloc (sizeof (char) * LOW_BUFF);
        if(clamd_local == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        } else {
            xstrncpy(clamd_local, first, LOW_BUFF);
        }
        free(type);
        free(first);
        return 1;
    }

    if (strcmp(type, "maxsize") == 0) {
        maxsize = ci_strto_off_t(first, &end, 10);
        if ((maxsize == 0 && errno != 0) || maxsize < 0)
            maxsize = 0;
        if (*end == 'k' || *end == 'K')
            maxsize = maxsize * 1024;
        else if (*end == 'm' || *end == 'M')
            maxsize = maxsize * 1024 * 1024;
        else if (*end == 'g' || *end == 'G')
            maxsize = maxsize * 1024 * 1024 * 1024;
        maxsize = max(maxsize, banmaxsize);
        free(type);
        free(first);
        return 1;
    }

    /* Scan mode */
    if(strcmp(type, "scan_mode") == 0) {
	char *scan_type = (char *) malloc (sizeof (char) * LOW_BUFF);
        if(scan_type == NULL) {
            fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
            free(scan_type);
            free(type);
            free(first);
            return 0;
        } else {
            if (strncmp(first, "ScanNothingExcept", sizeof (char) * LOW_BUFF) == 0) {
                scan_mode = SCAN_NONE;
                debugs(0, "LOG setting squidclamav scan mode to 'ScanNothingExcept'.\n");
	    } else if (strncmp(first, "ScanAllExcept", sizeof (char) * LOW_BUFF) == 0) {
                scan_mode = SCAN_ALL;
                debugs(0, "LOG setting squidclamav scan mode to 'ScanAllExcept'.\n");
            } else if (strlen(first) > 0) {
                fprintf(stderr, "incorrect value in scan_mode, failling back to ScanAllExcept mode.\n");
                scan_mode = SCAN_ALL;
            }
        }
        free(scan_type);
        free(type);
        free(first);
        return 1;
    }


    /* force case insensitive pattern matching */
    /* so aborti, contenti, regexi are now obsolete */
    regex_flags |= REG_ICASE;
    /* Add extended regex search */
    regex_flags |= REG_EXTENDED;

    /* Fill the pattern type */
    if (strcmp(type, "abort") == 0) {
        currItem.type = ABORT;
    } else if (strcmp(type, "abortcontent") == 0) {
        currItem.type = ABORTCONTENT;
    } else if (strcmp(type, "scan") == 0) {
        currItem.type = SCAN;
    } else if (strcmp(type, "scancontent") == 0) {
        currItem.type = SCANCONTENT;
#ifdef HAVE_LIBARCHIVE
    /* libarchive support */
    } else if (strcmp(type, "ban_archive_entry") == 0) {
        currItem.type = BANFILE;
        banfile = 1;
#endif
    } else if (strcmp(type, "whitelist") == 0 || strcmp(type, "blacklist") == 0) {
        currItem.type = WHITELIST;
	if (strcmp(type, "blacklist") == 0)
		currItem.type = BLACKLIST;
	if (level == 0) {
		if (readFileContent(first, type) == 1) {
			free(type);
			free(first);
			return 1;
		}
	}
    } else if(strcmp(type, "trustuser") == 0) {
        currItem.type = TRUSTUSER;
    } else if(strcmp(type, "trustclient") == 0) {
        currItem.type = TRUSTCLIENT;
    } else if(strcmp(type, "untrustuser") == 0) {
        currItem.type = UNTRUSTUSER;
    } else if(strcmp(type, "untrustclient") == 0) {
        currItem.type = UNTRUSTCLIENT;
    } else if ( (strcmp(type, "squid_ip") != 0) && (strcmp(type, "squid_port") != 0) && (strcmp(type, "maxredir") != 0) && (strcmp(type, "useragent") != 0) && (strcmp(type, "trust_cache") != 0) ) {
        fprintf(stderr, "WARNING Bad configuration keyword: %s\n", s);
        free(type);
        free(first);
        return 1;
    }

    /* Fill the pattern flag */
    currItem.flag = regex_flags;

    /* Fill pattern array */
    currItem.pattern = malloc(sizeof(char)*(strlen(first)+1));
    if (currItem.pattern == NULL) {
        fprintf(stderr, "unable to allocate new pattern in add_to_patterns()\n");
        free(type);
        free(first);
        return 0;
    }
    strcpy(currItem.pattern, first);
    if ((stored = regcomp(&currItem.regexv, currItem.pattern, currItem.flag)) != 0) {
        debugs(0, "ERROR Invalid regex pattern: %s\n", currItem.pattern);
    } else {
        if (growPatternArray(currItem) < 0) {
            fprintf(stderr, "unable to allocate new pattern in add_to_patterns()\n");
            free(type);
            free(first);
            return 0;
        }
    }
    free(type);
    free(first);
    return 1;
}

/* return 1 when the file have some regex content, 0 otherwise */
int
readFileContent(char *filepath, char *kind)
{
    char *buf = NULL;
    FILE *fp  = NULL;
    int ret   = 0;
    char str[LOW_BUFF+LOW_CHAR+1];

    if (isFileExists(filepath) != 0) {
	return 0;
    }

    debugs(0, "LOG Reading %s information from file from %s\n", kind, filepath);
    fp = fopen(filepath, "rt");
    if (fp == NULL) {
        debugs(0, "FATAL unable to open %s file: %s\n", kind, filepath);
        return 0;
    }

    buf = (char *)malloc(sizeof(char)*LOW_BUFF*2);
    if (buf == NULL) {
        debugs(0, "FATAL unable to allocate memory in readFileContent()\n");
        fclose(fp);
        return 0;
    }
    while ((fgets(buf, LOW_BUFF, fp) != NULL)) {
        /* chop newline */
        chomp(buf);
        /* add to regex patterns array */
        snprintf(str, LOW_CHAR + LOW_BUFF, "%s %s", kind, buf);
        if ( (strlen(buf) > 0) && (add_pattern(str, 1) == 0) ) {
            free(buf);
            fclose(fp);
            return 0;
        }
    }
    free(buf);
    ret = fclose(fp);
    if (ret != 0) {
        debugs(0, "ERROR Can't close file %s (%d)\n", filepath, ret);
    }

    return 1;
}

int extract_http_info(ci_request_t * req, ci_headers_list_t * req_header,
                      struct http_info *httpinf)
{
    char *str;
    int i = 0;

    /* Format of the HTTP header we want to parse:
       GET http://www.squid-cache.org/Doc/config/icap_service HTTP/1.1
       */
    httpinf->url[0]='\0';
    httpinf->method[0] = '\0';

    str = req_header->headers[0];

    /* if we can't find a space character, there's somethings wrong */
    if (strchr(str, ' ') == NULL) {
        return 0;
    }

    /* extract the HTTP method */
    while (*str != ' ' && i < (MAX_METHOD_SIZE - 1)) {
        httpinf->method[i] = *str;
        str++;
        i++;
    }
    httpinf->method[i] = '\0';
    debugs(3, "DEBUG method %s\n", httpinf->method);

    /* Extract the URL part of the header */
    while (*str == ' ') str++;
    i = 0;
    while (*str != ' ' && i < (MAX_URL - 1)) {
        httpinf->url[i] = *str;
        i++;
        str++;
    }
    httpinf->url[i] = '\0';
    debugs(3, "DEBUG url %s\n", httpinf->url);
    if (*str != ' ') {
        return 0;
    }
    /* we must find the HTTP version after all */
    while (*str == ' ')
        str++;
    if (*str != 'H' || *(str + 4) != '/') {
        return 0;
    }

    return 1;
}

const char *http_content_type(ci_request_t * req)
{
    ci_headers_list_t *heads;
    const char *val;
    if (!(heads =  ci_http_response_headers(req))) {
        /* Then maybe is a reqmod request, try to get request headers */
        if (!(heads = ci_http_request_headers(req)))
            return NULL;
    }
    if (!(val = ci_headers_value(heads, "Content-Type")))
        return NULL;

    return val;
}

void free_global()
{
    free(clamd_local);
    free(clamd_ip);
    free(clamd_port);
    free(clamd_curr_ip);
    free(redirect_url);
#ifdef HAVE_LIBARCHIVE
    /* libarchive support */
    free(recover_path);
#endif
    if (patterns != NULL) {
        while (pattc > 0) {
            pattc--;
            regfree(&patterns[pattc].regexv);
            free(patterns[pattc].pattern);
        }
        free(patterns);
        patterns = NULL;
    }
}

void free_pipe()
{
    if (sgfpw) fclose(sgfpw);
    if (sgfpr) fclose(sgfpr);
}

static const char *blocked_header_message =
"<html>\n"
"<body>\n"
"<p>\n"
"You will be redirected in few seconds, if not use this <a href=\"";

static const char *blocked_footer_message =
"\">direct link</a>.\n"
"</p>\n"
"</body>\n"
"</html>\n";

void generate_response_page(ci_request_t *req, av_req_data_t *data)
{
    chomp(data->malware);

    if (redirect_url != NULL) {
        char *urlredir = (char *) malloc( sizeof(char)*MAX_URL );
        snprintf(urlredir, MAX_URL, "%s?url=%s&source=%s&user=%s&virus=%s&recover=%s"
                 , redirect_url
		 , data->url
		 , data->clientip
		 , data->user
		 , data->malware
		 , data->recover
		 );
        if (logredir == 0)
            debugs((logredir==0) ? 1 : 0, "Virus redirection: %s.\n", urlredir);
        generate_redirect_page(urlredir, req, data);
        free(urlredir);
#ifdef HAVE_CICAP_TEMPLATE
    } else {
        generate_template_page(req, data);
#endif
    }
}

#ifdef HAVE_CICAP_TEMPLATE
int fmt_malware(ci_request_t *req, char *buf, int len, const char *param)
{
   av_req_data_t *data = ci_service_data(req);
   char *malware = data->malware;

   if (strncmp("stream: ", malware, strlen("stream: ")) == 0)
       malware += 8;

   memset(buf, '\0', len);
   len = strlen(malware) - strlen(" FOUND") + 1;
   xstrncpy(buf, malware, len);

   return strlen(buf);
}

void generate_template_page(ci_request_t *req, av_req_data_t *data)
{
    char buf[LOG_URL_SIZE];
    char *malware;
    int len;

    if (strncmp("stream: ", data->malware, strlen("stream: ")) == 0)
       data->malware += 8;

    debugs(0, "LOG Virus found in %s ending download [%s]\n", data->url, data->malware);

    len = strlen(data->malware) - strlen(" FOUND") + 1;
    malware = (char *) malloc (sizeof (char) * len);
    memset(malware, 0, sizeof (char) * len);
    xstrncpy(malware, data->malware, len);

    if ( ci_http_response_headers(req))
	ci_http_response_reset_headers(req);
    else
       ci_http_response_create(req, 1, 1);
    ci_http_response_add_header(req, "HTTP/1.0 403 Forbidden");
    ci_http_response_add_header(req, "Server: C-ICAP");
    ci_http_response_add_header(req, "Connection: close");
    ci_http_response_add_header(req, "Content-Type: text/html");

    /*
	This header is a shorter alternative to the X-Infection-Found header. On
	a single line it can contain any virus or threat description. The ICAP
	client MAY log this information.
    */
    snprintf(buf, LOW_BUFF, "X-Virus-ID: %s", (malware[0] != '\0') ? malware : "Unknown virus");
    buf[sizeof(buf)-1] = '\0';
    ci_icap_add_xheader(req, buf);
    ci_http_response_add_header(req, buf);

    /*
	The TypeID can currently be one of the following three values: zero for
	virus infections, one for mail policy violations (e.g. illegal file
	attachment name) or two for container violations (e.g. a zip file that
	takes too long to decompress).

	The ResolutionID can currently be one of the following three values:
	zero for a file that was not repaired, one if the returned file in the
	RESPMOD response is the repaired version of the infected file that was
	encapsulated in the request or two if the original file should be
	blocked or rejected due to container or mail policy violations.

	The ThreatDescription is a human-readable description of the threat, for
	example the virus name or the policy violation description. It MAY
	contain spaces, SHOULD NOT be quoted and MUST NOT contain semicolons
	because it is terminated by the final semicolon of the header
	definition.

    */
    snprintf(buf, LOW_BUFF, "X-Infection-Found: Type=0; Resolution=2; Threat=%s;", (malware[0] != '\0') ? malware : "Unknown virus");
    buf[sizeof(buf)-1] = '\0';
    ci_icap_add_xheader(req, buf);
    ci_http_response_add_header(req, buf);
    free(malware);

    data->error_page = ci_txt_template_build_content(req, "squidclamav", "MALWARE_FOUND", GlobalTable);
#ifdef HAVE_CICAP_HASALLDATA
    data->error_page->hasalldata = 1;
#else
    data->error_page->flags = CI_MEMBUF_HAS_EOF;
#endif

    snprintf(buf, LOW_BUFF, "Content-Language: %s",
             (char *)ci_membuf_attr_get(data->error_page, "lang"));
    buf[sizeof(buf)-1] = '\0';
    ci_http_response_add_header(req, buf);

    snprintf(buf, LOW_BUFF, "Content-Length: %d", (int)strlen(data->error_page->buf));
    buf[sizeof(buf)-1] = '\0';
    ci_http_response_add_header(req, buf);
}
#endif

void generate_redirect_page(char * redirect, ci_request_t * req, av_req_data_t * data)
{
    int new_size = 0;
    char buf[MAX_URL];
    ci_membuf_t *error_page;
    char *malware;
    int len;

    if (strncmp("stream: ", data->malware, strlen("stream: ")) == 0)
       data->malware += 8;

    len  = strlen(data->malware) - strlen(" FOUND") + 1;
    malware = (char *) malloc (sizeof (char) * len);
    memset(malware, 0, sizeof (char) * len);
    xstrncpy(malware, data->malware, len);

    new_size = strlen(blocked_header_message) + strlen(redirect) + strlen(blocked_footer_message) + 10;

    if ( ci_http_response_headers(req))
        ci_http_response_reset_headers(req);
    else
        ci_http_response_create(req, 1, 1);

    debugs(2, "DEBUG creating redirection page\n");

    snprintf(buf, MAX_URL, "Location: %s", redirect);
    /*strcat(buf, ";");*/

    debugs(3, "DEBUG %s\n", buf);

    ci_http_response_add_header(req, "HTTP/1.0 307 Temporary Redirect");
    ci_http_response_add_header(req, buf);
    ci_http_response_add_header(req, "Server: C-ICAP");
    ci_http_response_add_header(req, "Connection: close");
    ci_http_response_add_header(req, "Content-Type: text/html");
    ci_http_response_add_header(req, "Content-Language: en");
    snprintf(buf, LOW_BUFF, "X-Virus-ID: %s", (malware[0] != '\0') ? malware : "Unknown virus");
    buf[sizeof(buf)-1] = '\0';
    ci_icap_add_xheader(req, buf);
    ci_http_response_add_header(req, buf);
    snprintf(buf, LOW_BUFF, "X-Infection-Found: Type=0; Resolution=2; Threat=%s;", (malware[0] != '\0') ? malware : "Unknown virus");
    free(malware);
    buf[sizeof(buf)-1] = '\0';
    ci_icap_add_xheader(req, buf);
    ci_http_response_add_header(req, buf);

    if (data->blocked == 1) {
        error_page = ci_membuf_new_sized(new_size);
        ((av_req_data_t *) data)->error_page = error_page;
        ci_membuf_write(error_page, (char *) blocked_header_message, strlen(blocked_header_message), 0);
        ci_membuf_write(error_page, (char *) redirect, strlen(redirect), 0);
        ci_membuf_write(error_page, (char *) blocked_footer_message, strlen(blocked_footer_message), 1);
    }
    debugs(3, "DEBUG done\n");

}

int create_pipe(char *command)
{

    int pipe1[2];
    int pipe2[2];

    debugs(1, "DEBUG Open pipe to squidGuard %s!\n", command);

    if (command != NULL) {
        if ( pipe(pipe1) < 0  ||  pipe(pipe2) < 0 ) {
            debugs(0, "ERROR unable to open pipe, disabling call to %s.\n", command);
            perror("pipe");
            usepipe = 0;
        } else {
            if ( (pid = fork()) == -1) {
                debugs(0, "ERROR unable to fork, disabling call to %s.\n", command);
                usepipe = 0;
            } else {
                if(pid == 0) {
                    close(pipe1[1]);
                    dup2(pipe1[0],0);
                    close(pipe2[0]);
                    dup2(pipe2[1],1);
                    setsid();
                    /* Running chained program */
                    execlp(command,(char *)basename(command),(char  *)0);
                    exit(EXIT_SUCCESS);
                    return(0);
                } else {
                    close(pipe1[0]);
                    sgfpw = fdopen(pipe1[1], "w");
                    if (!sgfpw) {
                        debugs(0, "ERROR unable to fopen command's child stdin, disabling it.\n");
                        usepipe = 0;
                    } else {
                        /* make pipe line buffered */
                        if (setvbuf (sgfpw, (char *)NULL, _IOLBF, 0)  != 0)
                            debugs(1, "DEBUG unable to line buffering pipe.\n");
                        sgfpr = fdopen(pipe2[0], "r");
                        if(!sgfpr) {
                            debugs(0, "ERROR unable to fopen command's child stdout, disabling it.\n");
                            usepipe = 0;
                        } else {
                            debugs(1, "DEBUG bidirectional pipe to %s children ready...\n", command);
                            usepipe = 1;
                        }
                    }
                }
            }
        }
    }

    return 1;
}

int dconnect()
{
    struct sockaddr_un userver;
    int asockd;

    memset ((char *) &userver, 0, sizeof (userver));

    debugs(2, "entering.\n");
    if (clamd_local != NULL) {
        userver.sun_family = AF_UNIX;
        xstrncpy (userver.sun_path, clamd_local, sizeof(userver.sun_path));
        if ((asockd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
            debugs(0, "ERROR Can't bind local socket on %s.\n", clamd_local);
            return -1;
        }
        if (connect (asockd, (struct sockaddr *) &userver, sizeof (struct sockaddr_un)) < 0) {
            close (asockd);
            debugs(0, "ERROR Can't connect to clamd on local socket %s.\n", clamd_local);
            return -1;
        }
        return asockd;

    } else {
        if (clamd_curr_ip[0] != 0) {
            asockd = connectINET(clamd_curr_ip, atoi(clamd_port));
            if ( asockd != -1 ) {
                debugs(1, "DEBUG Connected to Clamd (%s:%s)\n", clamd_curr_ip,clamd_port);
                return asockd;
            }
        }

        char *ptr;
        char *s = (char *) malloc (sizeof (char) * SMALL_CHAR);
        xstrncpy(s, clamd_ip, SMALL_CHAR);
        ptr = strtok(s, ",");
        while (ptr != NULL) {
            asockd = connectINET(ptr, atoi(clamd_port));
            if ( asockd != -1 ) {
                debugs(1, "DEBUG Connected to Clamd (%s:%s)\n", ptr,clamd_port);
                /* Store last working clamd */
                xstrncpy(clamd_curr_ip, ptr, LOW_CHAR);
                break;
            }
            ptr = strtok(NULL, ",");
        }
        free(s);
        return asockd;
    }
    return 0;
}

void connect_timeout()
{
    // doesn't actually need to do anything
}
int connectINET(char *serverHost, uint16_t serverPort)
{
    struct sockaddr_in server;
    int asockd;
    struct sigaction action;
    struct addrinfo hints;
    struct addrinfo *res = NULL;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    action.sa_handler = connect_timeout;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;

    memset ((char *) &server, 0, sizeof (server));
    server.sin_addr.s_addr = inet_addr(serverHost);

    if ((asockd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
        debugs(0, "ERROR Can't create a socket.\n");
        return -1;
    }

    if (getaddrinfo (serverHost, NULL, &hints, &res) != 0)
    {
      close(asockd);
      debugs(0, "ERROR Can't lookup hostname of %s\n", serverHost);
      return -1;
    }

    server.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    server.sin_port = htons(serverPort);
    server.sin_family = AF_INET;

    sigaction(SIGALRM, &action, NULL);
    alarm(timeout);

    if (connect (asockd, (struct sockaddr *) &server, sizeof (struct sockaddr_in)) < 0) {
        close (asockd);
        if (res)
          freeaddrinfo(res);
        debugs(0, "ERROR Can't connect on %s:%d.\n", serverHost,serverPort);
        return -1;
    }
    int err = errno;
    alarm(0);
    if (err == EINTR) {
        if (res)
          freeaddrinfo(res);
        close(asockd);
        debugs(0, "ERROR Timeout connecting to clamd on %s:%d.\n", serverHost,serverPort);
    }

    if (res)
      freeaddrinfo(res);
    return asockd;
}

/**
 * Searches all occurrences of old into s
 * and replaces with new
 */
char * replace(const char *s, const char *old, const char *new)
{
    char *ret;
    int i, count = 0;
    size_t newlen = strlen(new);
    size_t oldlen = strlen(old);

    for (i = 0; s[i] != '\0'; i++) {
        if (strstr(&s[i], old) == &s[i]) {
            count++;
            i += oldlen - 1;
        }
    }
    ret = malloc(i + 1 + count * (newlen - oldlen));
    if (ret != NULL) {
        i = 0;
        while (*s) {
            if (strstr(s, old) == s) {
                strcpy(&ret[i], new);
                i += newlen;
                s += oldlen;
            } else {
                ret[i++] = *s++;
            }
        }
        ret[i] = '\0';
    }

    return ret;
}

int squidclamav_safebrowsing(ci_request_t * req, char *url, const char *clientip,
                             const char *username)
{
    av_req_data_t *data = ci_service_data(req);
    char cbuff[MAX_URL+60];
    char clbuf[SMALL_BUFF];

    ssize_t ret;
    int nbread = 0;
    int sockd;

    debugs(2, "DEBUG looking for Clamav SafeBrowsing check.\n");

    /* SCAN DATA HERE */
    if ((sockd = dconnect ()) < 0) {
        debugs(0, "ERROR Can't connect to Clamd daemon.\n");
        return 0;
    }
    debugs(2, "DEBUG Sending zINSTREAM command to clamd.\n");

    if (write(sockd, "zINSTREAM", 10) <= 0) {
        debugs(0, "ERROR Can't write to Clamd socket.\n");
        close(sockd);
        return 0;
    }

    debugs(2, "DEBUG Ok connected to clamd socket.\n");

    debugs(1, "DEBUG Scanning url for Malware now\n");
    uint32_t buf[LBUFSIZ/sizeof(uint32_t)];
    strcpy(cbuff, "From test\n\n<a href=");
    strncat(cbuff, url, MAX_URL);
    strcat(cbuff, ">squidclamav-safebrowsing-test</a>\n");
    size_t sfsize = 0;
    sfsize = strlen(cbuff);
    buf[0] = htonl(sfsize);
    memcpy(&buf[1],(const char*) cbuff, sfsize);
    debugs(3, "DEBUG sending %s\n", cbuff);
    ret = sendln (sockd,(const char *) buf, sfsize+sizeof(uint32_t));
    if ( ret <= 0 ) {
        debugs(0, "ERROR Can't write to clamd socket.\n");
    } else {
        debugs(3, "DEBUG Write to socket\n");
        memset(cbuff, 0, sizeof(cbuff));
        *buf = 0;
        ret = sendln (sockd,(const char *) buf, 4);
        if (ret <= 0)
        {
            debugs(0, "ERROR Can't write INSTREAM ending chars to clamd socket.\n");
        } else {
            memset (clbuf, 0, sizeof(clbuf));
            while ((nbread = read(sockd, clbuf, SMALL_BUFF - 1)) > 0) {
		clbuf[nbread] = '\0';
                debugs(2, "DEBUG received from Clamd: %s\n", clbuf);
                if (strstr (clbuf, "FOUND")) {
                    data->blocked = 1;
		    data->malware = ci_buffer_alloc(strlen(clbuf)+1);
		    strcpy(data->malware, clbuf);
                    debugs(0, "LOG Virus found in %s ending download [%s]\n", url, clbuf);
		    if (sockd > -1) {
			debugs(1, "DEBUG Closing Clamd connection.\n");
			close(sockd);
		    }
		    if ((data->url == NULL) && (url != NULL)) {
		        data->url = ci_buffer_alloc(strlen(url)+1);
		        strcpy(data->url, url);
		    }
		    if ((data->user == NULL) && (username != NULL)) {
		        data->user = ci_buffer_alloc(strlen(username)+1);
		        strcpy(data->user, username);
		    }
		    if ((data->clientip == NULL) && (clientip != NULL)) {
		        data->clientip = ci_buffer_alloc(strlen(clientip)+1);
		        strcpy(data->clientip, clientip);
		    }
                    generate_response_page(req, data);
                    return 1;
                }
                memset(clbuf, 0, sizeof(clbuf));
            }
        }
    }
    /* close socket to clamd */
    if (sockd > -1) {
        debugs(1, "DEBUG Closing Clamd connection.\n");
        close(sockd);
    }

    debugs(3, "DEBUG No malware found.\n");

    return 0;
}

#ifdef HAVE_LIBARCHIVE
/**
 * returns file name extension (libarchive)
 */
const char *get_filename_ext(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename)
        return "";
    return dot + 1;
}

/**
 * simple file copy (libarchive)
 */
int copy_file(int fd_src, const char  *fname_dst)
{
    char buf[HIGH_BUFF];
    ssize_t nread, total_read;
    int fd_dst;

    fd_dst = open(fname_dst, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if(fd_dst < 0) {
        debugs(0, "DEBUG libarchive could not create [%s]\n", fname_dst);
        return  -1;
    }

    total_read = 0;
    while (nread = read(fd_src, buf, sizeof(buf)), nread > 0) {
        total_read += nread;
        debugs(3, "DEBUG libarchive read [%d] bytes of data\n", (int) nread);
        char *out_ptr = buf;
        ssize_t written;
        do {
            written = write(fd_dst, out_ptr, nread);
            if (written >= 0) {
                nread -= written;
                out_ptr += written;
                debugs(3, "DEBUG libarchive %d bytes written\n", (int) written);
            } else {
                debugs(3, "DEBUG libarchive write error %d\n", (int) written);
            }
        } while (nread > 0);
    }

    debugs(3, "DEBUG libarchive closing %s (%d bytes)\n", fname_dst, (int) total_read);
    close(fd_dst);
    return  0;
}

/**
 * check for invalid chars in string (libarchive)
 */
int has_invalid_chars(const char *inv_chars, const char *target)
{
    const char *c = target;
    debugs(3, "DEBUG libarchive checking for troublesome chars [%s] in [%s]\n", inv_chars, target);
    while (*c) {
        if (strchr(inv_chars, *c)) {
            debugs(3, "WARNING libarchive found troublesome char [%c] in [%s]\n", *c, target);
            return 1;
        }
        c++;
    }
    debugs(3, "DEBUG libarchive no troublesome chars in [%s]\n", target);
    return 0;
}
#endif
