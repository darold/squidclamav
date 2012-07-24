/*
 *  Copyright (C) 2005-2012 Gilles Darold
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
#include <errno.h>
#include <signal.h>

/* Structure used to store information passed throught the module methods */
typedef struct av_req_data{
     ci_simple_file_t *body;
     ci_request_t *req;
     ci_membuf_t *error_page;
     int blocked;
     int no_more_scan;
     int virus;
     char *url;
     char *user;
     char *clientip;
} av_req_data_t;

static int SEND_PERCENT_BYTES = 0;
static ci_off_t START_SEND_AFTER = 1;

/*squidclamav service extra data ... */
ci_service_xdata_t *squidclamav_xdata = NULL;

int AVREQDATA_POOL = -1;

int squidclamav_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf);
int squidclamav_post_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf);
void squidclamav_close_service();
int squidclamav_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t *);
int squidclamav_end_of_data_handler(ci_request_t *);
void *squidclamav_init_request_data(ci_request_t * req);
void squidclamav_release_request_data(void *data);
int squidclamav_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t * req);

/* General functions */
void set_istag(ci_service_xdata_t * srv_xdata);

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

int debug = 0;
int statit = 0;
int timeout = 1;
char *redirect_url = NULL;
char *squidguard = NULL;
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

/* Used by pipe to squidGuard */
int usepipe = 0;
pid_t pid;
FILE *sgfpw = NULL;
FILE *sgfpr = NULL;


/* --------------- URL CHECK --------------------------- */

#define MAX_URL_SIZE  8192
#define MAX_METHOD_SIZE  16
#define SMALL_BUFF 1024

struct http_info {
    char method[MAX_METHOD_SIZE];
    char url[MAX_URL_SIZE];
};

int extract_http_info(ci_request_t *, ci_headers_list_t *, struct http_info *);
char *http_content_type(ci_request_t *);
void free_global ();
void free_pipe ();
void generate_redirect_page(char *, ci_request_t *, av_req_data_t *);
void cfgreload_command(char *, int, char **);
int create_pipe(char *command);
int dconnect (void);
int connectINET(char *serverHost, uint16_t serverPort);
char * replace(const char *s, const char *old, const char *new);

/* ----------------------------------------------------- */


int squidclamav_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf)
{
    unsigned int xops;

    ci_debug_printf(1, "DEBUG squidclamav_init_service: Going to initialize squidclamav\n");

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
	 ci_debug_printf(0, "FATAL squidclamav_init_service: error registering object_pool av_req_data_t\n");
	 return 0;
    }

    /* Reload configuration command */
    register_command("squidclamav:cfgreload", MONITOR_PROC_CMD | CHILDS_PROC_CMD, cfgreload_command);

     
    /*********************
       read config files
     ********************/
    clamd_curr_ip = (char *) malloc (sizeof (char) * 128);
    memset(clamd_curr_ip, 0, sizeof(clamd_curr_ip));

    if (load_patterns() == 0) {
	return 0;
    }

    return 1;
}

void cfgreload_command(char *name, int type, char **argv)
{
    ci_debug_printf(1, "DEBUG cfgreload_command: reload configuration command received\n");

    free_global();
    free_pipe();
    debug = 0;
    statit = 0;

    pattc = 0;
    current_pattern_size = 0;
    maxsize = 0;
    logredir = 0;
    dnslookup = 1;
    clamd_curr_ip = (char *) malloc (sizeof (char) * 128);
    memset(clamd_curr_ip, 0, sizeof(clamd_curr_ip));
    if (load_patterns() == 0)
       ci_debug_printf(0, "FATAL cfgreload_command: reload configuration command failed!\n");
    if (squidclamav_xdata)
       set_istag(squidclamav_xdata);

    if (squidguard != NULL) {
	ci_debug_printf(1, "DEBUG cfgreload_command: reopening pipe to %s\n", squidguard);
	create_pipe(squidguard);
    }

}

int squidclamav_post_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf)
{

    if (squidguard == NULL) return 0;

    ci_debug_printf(1, "DEBUG squidclamav_post_init_service: opening pipe to %s\n", squidguard);

    if (create_pipe(squidguard) == 1) {
	return 0;
    }

    return 1;
}

void squidclamav_close_service()
{
    ci_debug_printf(1, "DEBUG squidclamav_close_service: clean all memory!\n");
    free_global();
    free_pipe();
    ci_object_pool_unregister(AVREQDATA_POOL);
}

void *squidclamav_init_request_data(ci_request_t * req)
{
    int preview_size;
    av_req_data_t *data;

    preview_size = ci_req_preview_size(req);

    ci_debug_printf(1, "DEBUG squidclamav_init_request_data: initializing request data handler.\n");

    if (!(data = ci_object_pool_alloc(AVREQDATA_POOL))) {
	ci_debug_printf(0, "FATAL squidclamav_init_request_data: Error allocation memory for service data!!!");
	return NULL;
    }
    data->body = NULL;
    data->error_page = NULL;
    data->req = req;
    data->blocked = 0;
    data->no_more_scan = 0;
    data->virus = 0;

    return data;
}


void squidclamav_release_request_data(void *data)
{

     if (data) {
          ci_debug_printf(1, "DEBUG squidclamav_release_request_data: Releasing request data.\n");

        if (((av_req_data_t *) data)->body) {
           ci_simple_file_destroy(((av_req_data_t *) data)->body);
	   if (((av_req_data_t *) data)->url)
		ci_buffer_free(((av_req_data_t *) data)->url);
	   if (((av_req_data_t *) data)->user)
		ci_buffer_free(((av_req_data_t *) data)->user);
	   if (((av_req_data_t *) data)->clientip)
		ci_buffer_free(((av_req_data_t *) data)->clientip);
	}

        if (((av_req_data_t *) data)->error_page)
           ci_membuf_free(((av_req_data_t *) data)->error_page);

        ci_object_pool_free(data);
     }
}

int squidclamav_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t * req)
{
     ci_headers_list_t *req_header;
     struct http_info httpinf;
     av_req_data_t *data = ci_service_data(req); 
     char *clientip;
     struct hostent *clientname;
     unsigned long ip;
     char *username;
     char *content_type;
     ci_off_t content_length;
     char *chain_ret = NULL;
     char *ret = NULL;
     int chkipdone = 0;

     ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: processing preview header.\n");

     if (preview_data_len)
	ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: preview data size is %d\n", preview_data_len);

     /* Extract the HTTP header from the request */
     if ((req_header = ci_http_request_headers(req)) == NULL) {
	ci_debug_printf(0, "ERROR squidclamav_check_preview_handler: bad http header, aborting.\n");
	return CI_ERROR;
     }

     /* Get the Authenticated user */
     if ((username = ci_headers_value(req->request_header, "X-Authenticated-User")) != NULL) {
	ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: X-Authenticated-User: %s\n", username);
        /* if a TRUSTUSER match => no squidguard and no virus scan */
        if (simple_pattern_compare(username, TRUSTUSER) == 1) {
           ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: No squidguard and antivir check (TRUSTUSER match) for user: %s\n", username);
	   return CI_MOD_ALLOW204;
        }
     } else {
	/* set null client to - */
	username = (char *)malloc(sizeof(char)*2);
	strcpy(username, "-");
     }

     /* Check client Ip against SquidClamav trustclient */
     if ((clientip = ci_headers_value(req->request_header, "X-Client-IP")) != NULL) {
	ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: X-Client-IP: %s\n", clientip);
	ip = inet_addr(clientip);
	chkipdone = 0;
	if (dnslookup == 1) {
		if ( (clientname = gethostbyaddr((char *)&ip, sizeof(ip), AF_INET)) != NULL) {
			if (clientname->h_name != NULL) {
				/* if a TRUSTCLIENT match => no squidguard and no virus scan */
				if (client_pattern_compare(clientip, clientname->h_name) > 0) {
				   ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: No squidguard and antivir check (TRUSTCLIENT match) for client: %s(%s)\n", clientname->h_name, clientip);
				   return CI_MOD_ALLOW204;
				}
				chkipdone = 1;
			}
		  }
	}
	if (chkipdone == 0) {
		/* if a TRUSTCLIENT match => no squidguard and no virus scan */
		if (client_pattern_compare(clientip, NULL) > 0) {
		   ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: No squidguard and antivir check (TRUSTCLIENT match) for client: %s\n", clientip);
		   return CI_MOD_ALLOW204;
		}
	}
     } else {
	/* set null client to - */
	clientip = (char *)malloc(sizeof(char)*2);
	strcpy(clientip, "-");
     }
     
     /* Get the requested URL */
     if (!extract_http_info(req, req_header, &httpinf)) {
	/* Something wrong in the header or unknow method */
	ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: bad http header, aborting.\n");
	return CI_MOD_ALLOW204;
     }
     ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: URL requested: %s\n", httpinf.url);

     /* Check the URL against SquidClamav Whitelist */
     if (simple_pattern_compare(httpinf.url, WHITELIST) == 1) {
           ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: No squidguard and antivir check (WHITELIST match) for url: %s\n", httpinf.url);
	   return CI_MOD_ALLOW204;
     }

     
     /* Check URL header against squidGuard */
     if (usepipe == 1) {
	char *rbuff = NULL;
	ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: Sending request to chained program: %s\n", squidguard);
	ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: Request: %s %s %s %s\n", httpinf.url,clientip,username,httpinf.method);
	/* escaping escaped character to prevent unescaping by squidguard */
	rbuff = replace(httpinf.url, "%", "%25");
	fprintf(sgfpw,"%s %s %s %s\n",rbuff,clientip,username,httpinf.method);
	fflush(sgfpw);
	xfree(rbuff);
	/* the chained redirector must return empty line if ok or the redirection url */
	chain_ret = (char *)malloc(sizeof(char)*MAX_URL_SIZE);
	if (chain_ret != NULL) {
	   ret = fgets(chain_ret,MAX_URL_SIZE,sgfpr);
	   if ((ret != NULL) && (strlen(chain_ret) > 1)) {
		ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: Chained program redirection received: %s\n", chain_ret);
		if (logredir)
		   ci_debug_printf(0, "INFO Chained program redirection received: %s\n", chain_ret);
		/* Create the redirection url to squid */
		data->blocked = 1;
		generate_redirect_page(strtok(chain_ret, " "), req, data);
	        xfree(chain_ret);
	        chain_ret = NULL;
	        return CI_MOD_CONTINUE;
	   }
	   xfree(chain_ret);
	   chain_ret = NULL;
	}
     }

     /* CONNECT method (https) can not be scanned so abort */
     if (strcmp(httpinf.method, "CONNECT") == 0) {
	ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: method %s can't be scanned.\n", httpinf.method);
	return CI_MOD_ALLOW204;
     }

     /* Check the URL against SquidClamav abort */
     if (simple_pattern_compare(httpinf.url, ABORT) == 1) {
           ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: No antivir check (ABORT match) for url: %s\n", httpinf.url);
	   return CI_MOD_ALLOW204;
     }

     /* Get the content length header */
     content_length = ci_http_content_length(req);
     ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: Content-Length: %d\n", (int)content_length);

     if ((content_length > 0) && (maxsize > 0) && (content_length >= maxsize)) {
	ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: No antivir check, content-length upper than maxsize (%d > %d)\n", content_length, (int)maxsize);
	return CI_MOD_ALLOW204;
     }

     /* Get the content type header */
     if ((content_type = http_content_type(req)) != NULL) {
	ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: Content-Type: %s\n", content_type);
        /* Check the Content-Type against SquidClamav abortcontent */
        if (simple_pattern_compare(content_type, ABORTCONTENT)) {
           ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: No antivir check (ABORTCONTENT match) for content-type: %s\n", content_type);
	   return CI_MOD_ALLOW204;
        }
     }

     /* No data, so nothing to scan */
     if (!data || !ci_req_hasbody(req)) {
	 ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: No body data, allow 204\n");
          return CI_MOD_ALLOW204;
     }

     if (preview_data_len == 0) {
	ci_debug_printf(1, "DEBUG squidclamav_check_preview_handler: can not begin to scan url: No preview data.\n");
	return CI_MOD_ALLOW204;
     }

     data->url = ci_buffer_alloc(strlen(httpinf.url)+1);
     strcpy(data->url, httpinf.url);
     if (username != NULL) {
	     data->user = ci_buffer_alloc(strlen(username)+1);
	     strcpy(data->user, username);
     } else {
	data->user = NULL;
     }
     if (clientip != NULL) {
	data->clientip = ci_buffer_alloc(strlen(clientip)+1);
	strcpy(data->clientip, clientip);
     } else {
	ci_debug_printf(0, "ERROR squidclamav_check_preview_handler: clientip is null, you must set 'icap_send_client_ip on' into squid.conf\n");
	data->clientip = NULL;
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
	ci_debug_printf(1, "DEBUG squidclamav_read_from_net: No more antivir check, downloaded stream is upper than maxsize (%d>%d)\n", data->body->bytes_in, (int)maxsize);
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
	ci_debug_printf(2, "DEBUG squidclamav_write_to_net: ending here, content was blocked\n");
	return CI_EOF; 
     }
     if (data->virus == 1 && data->error_page == 0) {
	ci_debug_printf(2, "DEBUG squidclamav_write_to_net: ending here, virus was found\n");
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

int squidclamav_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof, ci_request_t * req)
{
     int ret = CI_OK;

     if (rbuf && rlen) {
           *rlen = squidclamav_read_from_net(rbuf, *rlen, iseof, req);
	   if (*rlen == CI_ERROR)
	      return CI_ERROR;
           else if (*rlen < 0)
	      ret = CI_OK;
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
     char cbuff[MAX_URL_SIZE];
     char clbuf[SMALL_BUFF];

     ssize_t ret;
     int nbread = 0;
     int loopw = 60;
     uint16_t port;
     struct sockaddr_in server;
     struct sockaddr_in peer;
     size_t peer_size;
     char *pt = NULL;
     int sockd;
     int wsockd; 
     unsigned long total_read;

     ci_debug_printf(2, "DEBUG squidclamav_end_of_data_handler: ending request data handler.\n");

     /* Nothing more to scan */
     if (!data || !data->body)
          return CI_MOD_DONE;

     if (data->blocked == 1) {
        ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: blocked content, sending redirection header + error page.\n");
	return CI_MOD_DONE;
     }

     body = data->body;
     if (data->no_more_scan == 1) {
        ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: no more data to scan, sending content.\n");
	ci_simple_file_unlock_all(body);
	return CI_MOD_DONE;
     }

     /* SCAN DATA HERE */
     if ((sockd = dconnect ()) < 0) {
	ci_debug_printf(0, "ERROR squidclamav_end_of_data_handler: Can't connect to Clamd daemon.\n");
	return CI_MOD_ALLOW204;
     }
     ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: Sending STREAM command to clamd.\n");

     if (write(sockd, "STREAM", 6) <= 0) {
	ci_debug_printf(0, "ERROR squidclamav_end_of_data_handler: Can't write to Clamd socket.\n");
	close(sockd);
	return CI_MOD_ALLOW204;
     }

     while (loopw > 0) {
	memset (cbuff, 0, sizeof(cbuff));
	ret = read (sockd, cbuff, MAX_URL_SIZE);
	if ((ret > -1) && (pt = strstr (cbuff, "PORT"))) {
	   pt += 5;
	   sscanf(pt, "%d", (int *) &port);
	   break;
	}
	loopw--;
     }
     if (loopw == 0) {
	ci_debug_printf(0, "ERROR squidclamav_end_of_data_handler: Clamd daemon not ready for stream scanning.\n");
	close(sockd);
	return CI_MOD_ALLOW204;
     }

     ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: Received port %d from clamd.\n", port);

     /* connect to clamd given port */
     if ((wsockd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
	ci_debug_printf(0, "ERROR squidclamav_end_of_data_handler: Can't create the Clamd socket.\n");
	close(sockd);
	return CI_MOD_ALLOW204;
     }

     server.sin_family = AF_INET;
     server.sin_port = htons (port);
     peer_size = sizeof (peer);

     if (getpeername(sockd, (struct sockaddr *) &peer, (socklen_t *) &peer_size) < 0) {
	ci_debug_printf(0, "ERROR squidclamav_end_of_data_handler: Can't get socket peer name.\n");
	close(sockd);
	return CI_MOD_ALLOW204;
     }
     switch (peer.sin_family) {
	case AF_UNIX:
	server.sin_addr.s_addr = inet_addr ("127.0.0.1");
	break;
	case AF_INET:
	server.sin_addr.s_addr = peer.sin_addr.s_addr;
	break;
	default:
	ci_debug_printf(0, "ERROR squidclamav_end_of_data_handler: Unexpected socket type: %d.\n", peer.sin_family);
	close(sockd);
	return CI_MOD_ALLOW204;
     }

     ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: Trying to connect to clamd [port: %d].\n", port);

     if (connect (wsockd, (struct sockaddr *) &server, sizeof (struct sockaddr_in)) < 0) {
	close(wsockd);
	ci_debug_printf(0, "ERROR squidclamav_end_of_data_handler: Can't connect to clamd [port: %d].\n", port);
	return CI_MOD_ALLOW204;
     }
     ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: Ok connected to clamd on port: %d.\n", port);

/*-----------------------------------------------------*/

     ci_debug_printf(1, "DEBUG: squidclamav_end_of_data_handler: Scanning data now\n");
     lseek(body->fd, 0, SEEK_SET);
     memset(cbuff, 0, sizeof(cbuff));
     total_read = 0;
     while (data->virus == 0 && (nbread = read(body->fd, cbuff, MAX_URL_SIZE)) > 0) {
	    total_read += nbread;
	    ret = write(wsockd, cbuff, nbread);
	    if ( (ret <= 0) && (total_read > 0) ) {
		ci_debug_printf(3, "ERROR squidclamav_end_of_data_handler: Can't write to clamd socket (maybe we reach clamd StreamMaxLength, total read: %ld).\n", total_read);
		break;
	    } else if ( ret <= 0 ) {
		ci_debug_printf(0, "ERROR squidclamav_end_of_data_handler: Can't write to clamd socket.\n");
		break;
	    } else {
		ci_debug_printf(3, "DEBUG squidclamav_end_of_data_handler: Write %d bytes on %d to socket\n", (int)ret, nbread);
	    }

	    memset(cbuff, 0, sizeof(cbuff));

     }

     /* close socket to clamd */
     if (wsockd > -1) {
        ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: End Clamd connection, attempting to read result.\n");
	close(wsockd);
     }

     memset (clbuf, 0, sizeof(clbuf));
     while ((nbread = read(sockd, clbuf, SMALL_BUFF)) > 0) {
	ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: received from Clamd: %s", clbuf);
	if (strstr (clbuf, "FOUND\n")) {
	   data->virus = 1;
	   if (!ci_req_sent_data(req)) {
		chomp(clbuf);
		char *urlredir = (char *) malloc( sizeof(char)*MAX_URL_SIZE );
		snprintf(urlredir, MAX_URL_SIZE, "%s?url=%s&source=%s&user=%s&virus=%s", redirect_url, data->url, data->clientip, data->user, clbuf);
		if (logredir == 0)
		   ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: Virus redirection: %s.\n", urlredir);
		if (logredir)
		    ci_debug_printf(0, "INFO squidclamav_end_of_data_handler: Virus redirection: %s.\n", urlredir);
		generate_redirect_page(urlredir, req, data);
		xfree(urlredir);
	   }
	   ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: Virus found, ending download.\n");
	   break;
	}
	memset(clbuf, 0, sizeof(clbuf));
     }
     /* close second socket to clamd */
     if (sockd > -1) {
        ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: Closing Clamd connection.\n");
	close(sockd);
     }

     if (data->virus) {
        ci_debug_printf(1, "DEBUG squidclamav_end_of_data_handler: Virus found, sending redirection header + error page.\n");
          return CI_MOD_DONE;
     }

     if (!ci_req_sent_data(req)) {
	ci_debug_printf(2, "DEBUG squidclamav_end_of_data_handler: Responding with allow 204\n");
	return CI_MOD_ALLOW204;
     }

     ci_debug_printf(3, "DEBUG squidclamav_end_of_data_handler: unlocking data to be sent.\n");
     ci_simple_file_unlock_all(body);

     return CI_MOD_DONE;
}

void set_istag(ci_service_xdata_t * srv_xdata)
{
     char istag[SERVICE_ISTAG_SIZE + 1];


     snprintf(istag, SERVICE_ISTAG_SIZE, "-%d-%s-%d%d",1, "squidclamav", 1, 0);
     istag[SERVICE_ISTAG_SIZE] = '\0';
     ci_service_set_istag(srv_xdata, istag);
     ci_debug_printf(2, "DEBUG set_istag: setting istag to %s\n", istag);
}

/* util.c */

/* NUL-terminated version of strncpy() */
void
xstrncpy (char *dest, const char *src, size_t n) {
	if ( (src == NULL) || (strcmp(src, "") == 0))
		return;
	strncpy(dest, src, n-1);
	dest[n-1] = 0;
}

/* Emulate the Perl chomp() method: remove \r and \n from end of string */
void
chomp (char *str)
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
int
isPathExists(const char *path)
{
    struct stat sb;

    if ( (path == NULL) || (strcmp(path, "") == 0) ) return -1;

    if (lstat(path, &sb) != 0) {
	return -1;
    }

    return 0;
}


/* return 0 if path is secure, -1 otherwise */
int
isPathSecure(const char *path)
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

/*
 *  xfree() - same as free(3).  Will not call free(3) if s == NULL.
 */
void
xfree(void *s)
{
    if (s != NULL)
        free(s);
    s = NULL;
}

/* Remove spaces and tabs from beginning and end of a string */
void
trim(char *str)
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
char**
split( char* str, const char* delim)
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
int
ptrarray_length(char** arr)
{
	int i = 0;
	while(arr[i] != NULL) i++;
	return i;
}

void *
xmallox (size_t len)
{
	void *memres = malloc (len);
	if (memres == NULL) {
		fprintf(stderr, "Running Out of Memory!!!\n");
		exit(EXIT_FAILURE);
	}
	return memres;
}

size_t
xstrnlen(const char *s, size_t n)
{
	const char *p = (const char *)memchr(s, 0, n);
	return(p ? p-s : n);
}


/* pattern.c */
   
int
isIpAddress(char *src_addr)
{
  char *ptr;
  int address;
  int i;
  char *s = (char *) malloc (sizeof (char) * LOW_CHAR);

  xstrncpy(s, src_addr, LOW_CHAR);
  
  /* make sure we have numbers and dots only! */
  if(strspn(s, "0123456789.") != strlen(s)) {
    xfree(s);
    return 1;
  }

  /* split up each number from string */
  ptr = strtok(s, ".");
  if(ptr == NULL) {
    xfree(s);
    return 1;
  }
  address = atoi(ptr);
  if(address < 0 || address > 255) {
    xfree(s);
    xfree(ptr);
    return 1;
  }
  
  for(i = 2; i < 4; i++) {
    ptr = strtok(NULL, ".");
    if (ptr == NULL) {
       xfree(s);
       return 1;
    }
    address = atoi(ptr);
    if (address < 0 || address > 255) {
       xfree(ptr);
       xfree(s);
       return 1;
    }
  }
  xfree(s);
  
  return 0;
}


int
simple_pattern_compare(char *str, const int type)
{
	int i = 0;  

	/* pass througth all regex pattern */
	for (i = 0; i < pattc; i++) {
		if ( (patterns[i].type == type) && (regexec(&patterns[i].regexv, str, 0, 0, 0) == 0) ) {
			switch(type) {
				/* return 1 if string matches whitelist pattern */
				case WHITELIST:
					if (debug > 0)
						ci_debug_printf(2, "DEBUG simple_pattern_compare: whitelist (%s) matched: %s\n", patterns[i].pattern, str);
					return 1;
				/* return 1 if string matches abort pattern */
				case ABORT:
					if (debug > 0)
						ci_debug_printf(2, "DEBUG simple_pattern_compare: abort (%s) matched: %s\n", patterns[i].pattern, str);
					return 1;
				/* return 1 if string matches trustuser pattern */
				case TRUSTUSER:
					if (debug > 0)
						ci_debug_printf(2, "DEBUG simple_pattern_compare: trustuser (%s) matched: %s\n", patterns[i].pattern, str);
					return 1;
				/* return 1 if string matches abortcontent pattern */
				case ABORTCONTENT:
					if (debug > 0)
						ci_debug_printf(2, "DEBUG simple_pattern_compare: abortcontent (%s) matched: %s\n", patterns[i].pattern, str);
					return 1;
				default:
					ci_debug_printf(0, "ERROR simple_pattern_compare: unknown pattern match type: %s\n", str);
					return -1;
			}
		}
	}

	/* return 0 otherwise */
	return 0;
}

int
client_pattern_compare(char *ip, char *name)
{
	int i = 0;  

	/* pass througth all regex pattern */
	for (i = 0; i < pattc; i++) {
		if (patterns[i].type == TRUSTCLIENT) {
			/* Look at client ip pattern matching */
			/* return 1 if string matches ip TRUSTCLIENT pattern */
			if (regexec(&patterns[i].regexv, ip, 0, 0, 0) == 0) {
				if (debug != 0)
					ci_debug_printf(2, "DEBUG client_pattern_compare: trustclient (%s) matched: %s\n", patterns[i].pattern, ip);
				return 1;
			/* Look at client name pattern matching */
			/* return 2 if string matches fqdn TRUSTCLIENT pattern */
			} else if ((name != NULL) && (regexec(&patterns[i].regexv, name, 0, 0, 0) == 0)) {
				if (debug != 0)
					ci_debug_printf(2, "DEBUG client_pattern_compare: trustclient (%s) matched: %s\n", patterns[i].pattern, name);
				return 2;
			}
		}
	}

	/* return 0 otherwise */
	return 0;
}

/* scconfig.c */

/* load the squidclamav.conf */
int
load_patterns()
{
  char *buf = NULL;
  FILE *fp  = NULL;

  if (isPathExists(CONFIG_FILE) == 0) {
    fp = fopen(CONFIG_FILE, "rt");
    if (debug > 0)
       ci_debug_printf(0, "LOG load_patterns: Reading configuration from %s\n", CONFIG_FILE);
  }
  

  if (fp == NULL) {
	ci_debug_printf(0, "FATAL load_patterns: unable to open configuration file: %s\n", CONFIG_FILE);
    return 0;
  }

  buf = (char *)malloc(sizeof(char)*LOW_BUFF*2);
  if (buf == NULL) {
	ci_debug_printf(0, "FATAL load_patterns: unable to allocate memory in load_patterns()\n");
	fclose(fp);
	return 0;
  }
  while ((fgets(buf, LOW_BUFF, fp) != NULL)) {
      /* chop newline */
      chomp(buf);
      /* add to regex patterns array */
     if (add_pattern(buf) == 0) {
	xfree(buf);
	fclose(fp);
	return 0;
     }
  }
  xfree(buf);
  if (redirect_url == NULL) {
    ci_debug_printf(0, "FATAL load_patterns: No redirection URL set, going to BRIDGE mode\n");
    return 0;
  }
   if (squidguard != NULL) {
    ci_debug_printf(0, "LOG load_patterns: Chaining with %s\n", squidguard);
  }
  if (fclose(fp) != 0)
	ci_debug_printf(0, "ERROR load_patterns: Can't close configuration file\n");

  /* Set default values */
  if (clamd_local == NULL) {
	  if (clamd_ip == NULL) {
		clamd_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
		if(clamd_ip == NULL) {
			ci_debug_printf(0, "FATAL load_patterns: unable to allocate memory in load_patterns()\n");
			return 0;
		}
		xstrncpy(clamd_ip, CLAMD_SERVER, SMALL_CHAR);
	  }

	  if (clamd_port == NULL) {
		clamd_port = (char *) malloc (sizeof (char) * LOW_CHAR);
		if(clamd_port == NULL) {
			ci_debug_printf(0, "FATAL load_patterns: unable to allocate memory in load_patterns()\n");
			return 0;
		}
		xstrncpy(clamd_port, CLAMD_PORT, LOW_CHAR);
	  }
  }

  return 1;
}

int
growPatternArray (SCPattern item)
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
int
add_pattern(char *s)
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
		ci_debug_printf(0, "FATAL add_patterns: Bad configuration line for [%s]\n", s);
		xfree(type);
		xfree(first);
		return 0;
	}
	/* remove extra space or tabulation */
	trim(first);

	/* URl to redirect Squid on virus found */  
	if(strcmp(type, "redirect") == 0) {
		redirect_url = (char *) malloc (sizeof (char) * LOW_BUFF);
		if(redirect_url == NULL) {
			fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
			xfree(type);
			xfree(first);
			return 0;
		} else {
			xstrncpy(redirect_url, first, LOW_BUFF);
		}
		xfree(type);
		xfree(first);
		return 1;
	}

	/* Path to chained other Squid redirector, mostly SquidGuard */
	if(strcmp(type, "squidguard") == 0) {
		squidguard = (char *) malloc (sizeof (char) * LOW_BUFF);
		if(squidguard == NULL) {
			fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
			xfree(type);
			xfree(first);
			return 0;
		} else {
			if (isPathExists(first) == 0) {
				xstrncpy(squidguard, first, LOW_BUFF);
			} else {
				ci_debug_printf(0, "LOG add_patterns: Wrong path to SquidGuard, disabling.\n");
				squidguard = NULL;
			}
		}
		xfree(type);
		xfree(first);
		return 1;
	}
  
	if(strcmp(type, "debug") == 0) {
		if (debug == 0)
		   debug = atoi(first);
		xfree(type);
		xfree(first);
		return 1;
	}

	if(strcmp(type, "logredir") == 0) {
		if (logredir == 0)
		   logredir = atoi(first);
		xfree(type);
		xfree(first);
		return 1;
	}

	if(strcmp(type, "dnslookup") == 0) {
		if (dnslookup == 1)
		   dnslookup = atoi(first);
		xfree(type);
		xfree(first);
		return 1;
	}

	if(strcmp(type, "timeout") == 0) {
		timeout = atoi(first);
		if (timeout > 10)
			timeout = 10;
		xfree(type);
		xfree(first);
		return 1;
	}

	if(strcmp(type, "stat") == 0) {
		statit = atoi(first);
		xfree(type);
		xfree(first);
		return 1;
	}

	if(strcmp(type, "clamd_ip") == 0) {
		clamd_ip = (char *) malloc (sizeof (char) * SMALL_CHAR);
		if (clamd_ip == NULL) {
			fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
			xfree(type);
			xfree(first);
			return 0;
		} else {
			xstrncpy(clamd_ip, first, SMALL_CHAR);
		}
		xfree(type);
		xfree(first);
		return 1;
	}

	if(strcmp(type, "clamd_port") == 0) {
		clamd_port = (char *) malloc (sizeof (char) * LOW_CHAR);
		if(clamd_port == NULL) {
			fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
			xfree(type);
			xfree(first);
			return 0;
		} else {
			xstrncpy(clamd_port, first, LOW_CHAR);
		}
		xfree(type);
		xfree(first);
		return 1;
	}

	if(strcmp(type, "clamd_local") == 0) {
		clamd_local = (char *) malloc (sizeof (char) * LOW_BUFF);
		if(clamd_local == NULL) {
			fprintf(stderr, "unable to allocate memory in add_to_patterns()\n");
			xfree(type);
			xfree(first);
			return 0;
		} else {
			xstrncpy(clamd_local, first, LOW_BUFF);
		}
		xfree(type);
		xfree(first);
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
		xfree(type);
		xfree(first);
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
	} else if(strcmp(type, "whitelist") == 0) {
		currItem.type = WHITELIST;
	} else if(strcmp(type, "trustuser") == 0) {
		currItem.type = TRUSTUSER;
	} else if(strcmp(type, "trustclient") == 0) {
		currItem.type = TRUSTCLIENT;
	} else if ( (strcmp(type, "squid_ip") != 0) && (strcmp(type, "squid_port") != 0) && (strcmp(type, "maxredir") != 0) && (strcmp(type, "useragent") != 0) && (strcmp(type, "trust_cache") != 0) ) {
		fprintf(stderr, "WARNING: Bad configuration keyword: %s\n", s);
		xfree(type);
		xfree(first);
		return 1;
	}

	/* Fill the pattern flag */
	currItem.flag = regex_flags;

	/* Fill pattern array */
	currItem.pattern = malloc(sizeof(char)*(strlen(first)+1));
	if (currItem.pattern == NULL) {
		fprintf(stderr, "unable to allocate new pattern in add_to_patterns()\n");
		xfree(type);
		xfree(first);
		return 0;
	}
	strncpy(currItem.pattern, first, strlen(first) + 1);
	if ((stored = regcomp(&currItem.regexv, currItem.pattern, currItem.flag)) != 0) {
		ci_debug_printf(0, "ERROR add_pattern: Invalid regex pattern: %s\n", currItem.pattern);
	} else {
		if (growPatternArray(currItem) < 0) {
			fprintf(stderr, "unable to allocate new pattern in add_to_patterns()\n");
			xfree(type);
			xfree(first);
			return 0;
		}
	}
	xfree(type);
	xfree(first);
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
     while (*str != ' ' && i < MAX_METHOD_SIZE) {
	httpinf->method[i] = *str;
        str++;
	i++;
     }
     httpinf->method[i] = '\0';
     ci_debug_printf(3, "DEBUG extract_http_info: method %s\n", httpinf->method);

     /* Extract the URL part of the header */
     while (*str == ' ') str++;
     i = 0;
     while (*str != ' ' && i < MAX_URL_SIZE) {
	httpinf->url[i] = *str;
	i++;
	str++;
     }
     httpinf->url[i] = '\0';
     ci_debug_printf(3, "DEBUG extract_http_info: url %s\n", httpinf->url);
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

char *http_content_type(ci_request_t * req)
{
     ci_headers_list_t *heads;
     char *val;
     if (!(heads =  ci_http_response_headers(req))) {
          /* Then maybe is a reqmod request, try to get request headers */
          if (!(heads = ci_http_request_headers(req)))
               return NULL;
     }
     if (!(val = ci_headers_value(heads, "Content-Type")))
          return NULL;

     return val;
}

void
free_global ()
{
     xfree(clamd_local);
     xfree(clamd_ip);
     xfree(clamd_port);
     xfree(clamd_curr_ip);
     xfree(redirect_url);
     if (patterns != NULL) {
	while (pattc > 0) {
	   pattc--;
	   regfree(&patterns[pattc].regexv);
	   xfree(patterns[pattc].pattern);
	}
	free(patterns);
	patterns = NULL;
     }
}

void
free_pipe ()
{
     xfree(squidguard);
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

void generate_redirect_page(char * redirect, ci_request_t * req, av_req_data_t * data)
{
     int new_size = 0;
     char buf[MAX_URL_SIZE];
     ci_membuf_t *error_page;

     new_size = strlen(blocked_header_message) + strlen(redirect) + strlen(blocked_footer_message) + 10;

     if ( ci_http_response_headers(req))
          ci_http_response_reset_headers(req);
     else
          ci_http_response_create(req, 1, 1);

     ci_debug_printf(2, "DEBUG generate_redirect_page: creating redirection page\n");

     snprintf(buf, MAX_URL_SIZE, "Location: %s", redirect);
     /*strcat(buf, ";");*/

     ci_debug_printf(3, "DEBUG generate_redirect_page: %s\n", buf);

     ci_http_response_add_header(req, "HTTP/1.0 301 Moved Permanently");
     ci_http_response_add_header(req, buf);
     ci_http_response_add_header(req, "Server: C-ICAP");
     ci_http_response_add_header(req, "Connection: close");
     /*ci_http_response_add_header(req, "Content-Type: text/html;");*/
     ci_http_response_add_header(req, "Content-Type: text/html");
     ci_http_response_add_header(req, "Content-Language: en");

     if (data->blocked == 1) {
	error_page = ci_membuf_new_sized(new_size);
	((av_req_data_t *) data)->error_page = error_page;
	ci_membuf_write(error_page, (char *) blocked_header_message, strlen(blocked_header_message), 0);
	ci_membuf_write(error_page, (char *) redirect, strlen(redirect), 0);
	ci_membuf_write(error_page, (char *) blocked_footer_message, strlen(blocked_footer_message), 1);
     }
     ci_debug_printf(3, "DEBUG generate_redirect_page: done\n");

}

int create_pipe(char *command)
{

    int pipe1[2];
    int pipe2[2];

    ci_debug_printf(1, "DEBUG create_pipe: Open pipe to squidGuard %s!\n", command);

    if (command != NULL) {
	if ( pipe(pipe1) < 0  ||  pipe(pipe2) < 0 ) {
		ci_debug_printf(0, "ERROR create_pipe: unable to open pipe, disabling call to %s.\n", command);
		perror("pipe");
		usepipe = 0;
	} else {
		if ( (pid = fork()) == -1) {
			ci_debug_printf(0, "ERROR create_pipe: unable to fork, disabling call to %s.\n", command);
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
				   ci_debug_printf(0, "ERROR create_pipe: unable to fopen command's child stdin, disabling it.\n");
					usepipe = 0;
				} else {
					/* make pipe line buffered */
					if (setvbuf (sgfpw, (char *)NULL, _IOLBF, 0)  != 0)
						ci_debug_printf(1, "DEBUG create_pipe: unable to line buffering pipe.\n");
					sgfpr = fdopen(pipe2[0], "r");
					if(!sgfpr) {
						ci_debug_printf(0, "ERROR create_pipe: unable to fopen command's child stdout, disabling it.\n");
						usepipe = 0;
					} else {
						ci_debug_printf(1, "DEBUG create_pipe: bidirectional pipe to %s childs ready...\n", command);
						usepipe = 1;
					}
				}
			}
		}
	}
    }

    return 1;
}

int
dconnect ()
{
  struct sockaddr_un userver;
  int asockd;


  memset ((char *) &userver, 0, sizeof (userver));

  ci_debug_printf(1, "dconnect: entering.\n");
  if (clamd_local != NULL) {
      userver.sun_family = AF_UNIX;
      xstrncpy (userver.sun_path, clamd_local, sizeof(userver.sun_path));
      if ((asockd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
          ci_debug_printf(0, "ERROR dconnect: Can't bind local socket on %s.\n", clamd_local);
          return -1;
      }
      if (connect (asockd, (struct sockaddr *) &userver, sizeof (struct sockaddr_un)) < 0) {
          close (asockd);
          ci_debug_printf(0, "ERROR dconnect: Can't connect to clamd on local socket %s.\n", clamd_local);
          return -1;
      }
      return asockd;

    } else {
        if (clamd_curr_ip[0] != 0) {
                asockd = connectINET(clamd_curr_ip, atoi(clamd_port));
                if ( asockd != -1 ) {
                   ci_debug_printf(1, "DEBUG dconnect: Connected to Clamd (%s:%s)\n", clamd_curr_ip,clamd_port);
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
                    ci_debug_printf(1, "DEBUG dconnect: Connected to Clamd (%s:%s)\n", ptr,clamd_port);
                    /* Store last working clamd */
                    xstrncpy(clamd_curr_ip, ptr, LOW_CHAR);
                    xfree(s);
                    break;
                }
                ptr = strtok(NULL, ",");
        }
        return asockd;
        xfree(s);
    }
    return 0;
}

void connect_timeout() {
   // doesn't actually need to do anything
}

int
connectINET(char *serverHost, uint16_t serverPort)
{
        struct sockaddr_in server;
        struct hostent *he;
        int asockd;
	struct sigaction action;
	action.sa_handler = connect_timeout;

        memset ((char *) &server, 0, sizeof (server));
        server.sin_addr.s_addr = inet_addr(serverHost);
        if ((asockd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
          ci_debug_printf(0, "ERROR connectINET: Can't create a socket.\n");
          return -1;
        }

        server.sin_family = AF_INET;
        server.sin_port = htons(serverPort);

        if ((he = gethostbyname(serverHost)) == 0)
        {
          close(asockd);
          ci_debug_printf(0, "ERROR connectINET: Can't lookup hostname of %s\n", serverHost);
          return -1;
        }
        server.sin_addr = *(struct in_addr *) he->h_addr_list[0];
	sigaction(SIGALRM, &action, NULL);
	alarm(timeout);

        if (connect (asockd, (struct sockaddr *) &server, sizeof (struct sockaddr_in)) < 0) {
          close (asockd);
          ci_debug_printf(0, "ERROR connectINET: Can't connect on %s:%d.\n", serverHost,serverPort);
          return -1;
        }
	int err = errno;
	alarm(0);
	if (err == EINTR) {
          close(asockd);
	  ci_debug_printf(0, "ERROR connectINET: Timeout connecting to clamd on %s:%d.\n", serverHost,serverPort);
	}

        return asockd;
}


/**
 * Searches all occurrences of old into s
 * and replaces with new
 */
char *
replace(const char *s, const char *old, const char *new)
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

