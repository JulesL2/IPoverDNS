#ifndef GETIP_H_
#define GETIP_H_

typedef struct url_info
{
	char* protocol; // protocol type: http, ftp, etc...
	char* host; // host name
	int port; 	//port number
	char* path; //path without the first '/'
}url_info;

typedef struct http_reply {

    char *reply_buffer;
    int reply_buffer_length;
}http_reply ;



int download_page(url_info *info, http_reply *reply);

char* http_get_request(url_info *info);

char *read_http_reply(http_reply *reply);

int parse_url(char* url, url_info *info);

struct sockaddr_in* getip(void);

struct sockaddr_in* getlocalip(void);

#endif 