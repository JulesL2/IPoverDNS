#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

// for inet ntop
#include <arpa/inet.h>

#include "getip.h"

struct sockaddr_in *getlocalip(void)
{

    struct addrinfo *resultat, parametres;
    struct sockaddr_in *locale = malloc(sizeof(struct sockaddr_in));
    memset(&parametres, 0, sizeof(struct addrinfo));
    parametres.ai_family = AF_INET;
    parametres.ai_socktype = SOCK_STREAM;
    parametres.ai_protocol = 0;

    if (getaddrinfo("google.com", "80", &parametres, &resultat))
    {
        perror("ERREUR");
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Erreur sock");
    }

    if (connect(sock, resultat->ai_addr, resultat->ai_addrlen))
    {
        perror("Erreur connect");
        close(sock);
    }
    socklen_t socklen = sizeof(struct sockaddr);
    if (getsockname(sock, (struct sockaddr *)locale, &socklen))
    {
        perror("getsockname");
        close(sock);
    }
    close(sock); /*
     locale.sin_addr = ret.sin_addr;
     locale.sin_family = ret.sin_family;
     locale.sin_port = ret.sin_port;*/
    printf("IP Locale : %s\n", inet_ntoa(locale->sin_addr));
    return locale;
}

struct sockaddr_in *getip(void)
{
    url_info info;
    const char *file_name = "received_page";

    char *url = "http://myexternalip.com/raw";

    // First parse the URL
    info.host = "myexternalip.com";
    info.port = 80;
    info.path = "raw";
    info.protocol = "http://";

    // Download the page
    http_reply reply;

    int ret = download_page(&info, &reply);

    if (ret)
    {
        exit(1);
    }
    // Now parse the responses
    char *response = read_http_reply(&reply);
    if (response == NULL)
    {
        fprintf(stderr, "Could not parse http reply\n");
        exit(2);
    }
    printf("IP Address : %s\n", response);
    // Free allocated memory
    free(reply.reply_buffer);
    struct sockaddr_in *source = malloc(sizeof(struct sockaddr_in));
    source->sin_family = AF_INET;
    source->sin_port = htons(53);
    source->sin_addr.s_addr = inet_addr(response);
    /*
    struct sockaddr_in source;
    source.sin_family = AF_INET;
    source.sin_port = htons(53);
    source.sin_addr.s_addr = inet_addr(response); //IP source pour modifier dans la requete HTTP
    */
    return source;
}

int download_page(url_info *info, http_reply *reply)
{
    struct addrinfo *results, hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;      /* Allow IPv4 or IPv6 (AF_UNSPEC) Here IPV4 because socket can't connect with IPV6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    int r;
    r = getaddrinfo(info->host, NULL, &hints, &results);
    if (r != 0)
    {
        printf("Unable to get address info\n");
    }
    struct sockaddr *sock_addr_res;
    sock_addr_res = results->ai_addr;
    char ip[INET_ADDRSTRLEN];
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));

    int soc, connectfd;
    char *requete = http_get_request(info);

    struct sockaddr_in *addr_in = (struct sockaddr_in *)sock_addr_res;
    dest.sin_addr = addr_in->sin_addr;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(info->port);
    soc = socket(AF_INET, SOCK_STREAM, 0);
    connectfd = connect(soc, (struct sockaddr *)&dest, sizeof(struct sockaddr));

    if (connectfd != 0)
    {
        printf("Unable to connect\n");
    }

    write(soc, requete, strlen(requete));
    free(requete);
    int bytes_recv;
    int taille = sizeof(char) * 1000;
    int dernier_char = 0;
    char *buffer = malloc(taille);
    memset(buffer, 0, taille);
    reply->reply_buffer = buffer;
    bytes_recv = recv(soc, reply->reply_buffer, taille, 0);
    reply->reply_buffer_length = bytes_recv;

    if (reply->reply_buffer_length < 0)
    {
        fprintf(stderr, "recv returned error: %s\n", strerror(errno));
        return -1;
    }
    while (bytes_recv != 0)
    {
        taille = 2 * taille;
        reply->reply_buffer = realloc(reply->reply_buffer, taille);
        bytes_recv = recv(soc, reply->reply_buffer + reply->reply_buffer_length, taille - reply->reply_buffer_length, 0);
        reply->reply_buffer_length += bytes_recv;
        if (reply->reply_buffer_length < 0)
        {
            fprintf(stderr, "recv returned length %d error: %s\n", reply->reply_buffer_length, strerror(errno));
            return -1;
        }
    }

    int shdwn = shutdown(soc, SHUT_WR);
    reply->reply_buffer[reply->reply_buffer_length] = '\0';
    close(soc);
    return 0;
}

char *http_get_request(url_info *info)
{
    char *request_buffer = (char *)malloc(100 + strlen(info->path) + strlen(info->host));
    char port[4];
    snprintf(port, sizeof(port), "%d", info->port);
    snprintf(request_buffer, 1024, "GET /%s HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", info->path, info->host, port);
    return request_buffer;
}

char *next_line(char *buff, int len)
{
    if (len == 0)
    {
        return NULL;
    }

    char *last = buff + len - 1;
    while (buff != last)
    {
        if (*buff == '\r' && *(buff + 1) == '\n')
        {
            return buff;
        }
        buff++;
    }
    return NULL;
}

char *find_end_header(char *buff, int len)
{
    if (len == 0)
    {
        return NULL;
    }

    char *last = buff + len - 3;
    while (buff != last)
    {
        if (*buff == '\r' && *(buff + 1) == '\n' && *(buff + 2) == '\r' && *(buff + 3) == '\n')
        {
            return buff + 4;
        }
        buff++;
    }
    return NULL;
}

char *read_http_reply(http_reply *reply)
{
    // Let's first isolate the first line of the reply
    char *status_line = next_line(reply->reply_buffer, reply->reply_buffer_length);
    if (status_line == NULL)
    {
        fprintf(stderr, "Could not find status\n");
        return NULL;
    }
    *status_line = '\0'; // Make the first line is a null-terminated string

    // Now let's read the status (parsing the first line)
    int status;
    double http_version;
    int rv = sscanf(reply->reply_buffer, "HTTP/%lf %d", &http_version, &status);
    if (rv != 2)
    {
        fprintf(stderr, "Could not parse http response first line (rv=%d, %s)\n", rv, reply->reply_buffer);
        return NULL;
    }

    if (status != 200)
    {
        fprintf(stderr, "Server returned status %d (should be 200)\n", status);
        return NULL;
    }

    char *buf;
    buf = find_end_header(reply->reply_buffer, reply->reply_buffer_length); // new function that does what we want ie find the end of a line followed by an empty line
    return buf;
}
/*

int main(int argc, char *argv[])
{
    struct sockaddr_in* test = getlocalip();
    printf("test %s",inet_ntoa(test->sin_addr));
}
*/