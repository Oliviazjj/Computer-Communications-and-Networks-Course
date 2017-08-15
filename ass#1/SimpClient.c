/*------------------------------
* client.c
* Description: HTTP client program
* CSC 361
-------------------------------*/

/* define maximal string and reply length, this is just an example.*/
/* MAX_RES_LEN should be defined larger (e.g. 4096) in real testing. */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include<string.h>
#include <stdlib.h>
#include <netinet/in.h>
#define MAX_STR_LEN 120
#define MAX_RES_LEN 4096
/* --------- Main() routine ------------
 * three main task will be excuted:
 * accept the input URI and parse it into fragments for further operation
 * open socket connection with specified sockid ID
 * use the socket id to connect sopecified server
 * don't forget to handle errors
 */

main(int argc, char **argv)
{
    	char uri[MAX_STR_LEN];
    	char hostname[MAX_STR_LEN];
    	char identifier[MAX_STR_LEN];
    	int sockid, port;
	strcpy(uri,argv[1]);
   	parse_URI(uri, hostname, &port, identifier);
    	sockid = open_connection(hostname, port);
   	perform_http(sockid, identifier,uri, hostname);
}

/*------ Parse an "uri" into "hostname" and resource "identifier" --------*/

parse_URI(char *uri, char *hostname, int *port, char *identifier)
{
	char *hostB; /*beginning of the hostname */
	char *hostE; /*end of the hostname*/
	char *identB; /*beginning of the identifier*/
	int len;
	if (strncasecmp(uri, "http://", 7) != 0) {
	hostname[0] = '\0';
	exit(0);
    	}

    	/* Extract the host name */
    	hostB = uri + 7;
    	hostE = strpbrk(hostB, " :/\r\n\0");
    	len = hostE - hostB;
    	strncpy(hostname, hostB, len);
    	hostname[len] = '\0';

    	*port = 80; /* default port number is 80*/
    	if (*hostE == ':')
		*port = atoi(hostE + 1);

    	/* Extract the path */
    	identB = strchr(hostB, '/');
    	if (identB == NULL) {
		identifier[0] = '\0';
    	}
    	else {
		identB++;
		strcpy(identifier, identB);
    	}

    	return 0;
}

/*------------------------------------*
* connect to a HTTP server using hostname and port,
* and get the resource specified by identifier
*--------------------------------------*/
perform_http(int sockid, char *identifier, char *uri, char *hostname)
{
  /* connect to server and retrieve response */
	char REQUEST[MAX_STR_LEN];
	char recvline[MAX_RES_LEN];
    	bzero(recvline, sizeof(recvline));
	sprintf(REQUEST, "GET %s HTTP/1.0\r\nHost: %s\n%s\r\n\r\n", uri,hostname,"Connection: Keep-Alive");
	printf("---Request begin---\n");
	printf("%s", REQUEST);
	printf("---Request end---\nHTTP request sent, awaiting response...\n\n");
	int write_id = write(sockid, REQUEST, strlen(REQUEST)+1);
	if(write_id<0){
		perror("write failed");
		exit(0);
	}
	int read_id=read(sockid,recvline,sizeof(recvline));
	if(read_id<0){
		printf("read failed");
	}
	char *body;
	body=strstr(recvline,"\r\n\r\n");
	int lenHeader=strlen(recvline)-strlen(body);
	printf("---Response header---\n%.*s\n\n",lenHeader,recvline);
	printf("---Response body ---\n%s\n\n",body+4);
   	close(sockid);

}

/*---------------------------------------------------------------------------*
 *
 * open_conn() routine. It connects to a remote server on a specified port.
 *
 *---------------------------------------------------------------------------*/

int open_connection(char *hostname, int port)
{

  	int sockfd,connection_id;
  	/* generate socket
   	* connect socket to the host address
   	*/
	struct sockaddr_in server_addr;
	struct hostent *server_ent;
	memset(&server_addr, 0,sizeof(server_addr));
	server_ent= gethostbyname(hostname);
	memcpy(&server_addr.sin_addr, server_ent->h_addr, server_ent->h_length);
	if(!server_ent){
		perror("gethostbyname failed");
		exit(0);
	}
	sockfd=socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd<0){
		perror("ERROR opening socket");
      		exit(1);	
	}
	
	server_addr.sin_family = AF_INET;
  	server_addr.sin_port = htons(port);

	connection_id=connect(sockfd,(struct sockaddr *)&server_addr,sizeof(server_addr));
  	return sockfd;
}


