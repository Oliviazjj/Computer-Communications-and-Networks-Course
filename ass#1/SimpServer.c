/*------------------------------
* server.c
* Description: HTTP server program
* CSC 361
* Instructor: Kui Wu
-------------------------------*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#define MAX_STR_LEN 120         /* maximum string length */
#define SERVER_PORT_ID 9898     /* server port number */
#define HTTP_200 "HTTP/1.0 200 OK\r\n"
#define HTTP_404 "HTTP/1.0 404 Not Found\r\n"
#define HTTP_501 "HTTP/1.0 501 Not Implemented\r\n"
char sent[MAX_STR_LEN];
char PATH[MAX_STR_LEN];   /*buffle to store path*/
void cleanExit();

/*---------------------main() routine--------------------------*
 * tasks for main
 * generate socket and get socket id,
 * max number of connection is 3 (maximum length the queue of pending connections may grow to)
 * Accept request from client and generate new socket
 * Communicate with client and close new socket after done
 *---------------------------------------------------------------------------*/

main(int argc, char **argv)
{
	int newsockid; /* return value of the accept() call */
	int listen_fd;
	int port;
	int que_size=3;
	char buff[MAX_STR_LEN];
	struct sockaddr_in servaddr;
	if(argc ==3){
		port=atoi(argv[1]);
		strcpy(PATH,argv[2]);
	
	}else if(argc==2){
		port=80;
		strcpy(PATH,argv[1]);
	}else{
		printf("Argument error");
	}
	listen_fd=socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		close(listen_fd);
      		perror("ERROR opening socket");
      		exit(1);
   	}
	bzero( &servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
    	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    	servaddr.sin_port = htons(port);
	int bind_id=bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if(bind_id<0){
        	close(listen_fd);
		perror("ERROR on binding");
      		exit(1);
	}
    	int listen_id=listen(listen_fd, que_size);
	if (listen_id<0){
		close(listen_fd);
		perror("ERROR on listening");
      		exit(1);
	}
    	newsockid= accept(listen_fd, (struct sockaddr*) NULL, NULL);
 	if(newsockid<0){
 	    close(listen_fd);
 		perror("Error on accept");
		exit(1);
        }
	perform_http(newsockid);
    	/*wait for connection*/
	close(newsockid);
}

/*---------------------------------------------------------------------------*
 *
 * cleans up opened sockets when killed by a signal.
 *
 *---------------------------------------------------------------------------*/

void cleanExit()
{
    	exit(0);
}

/*---------------------------------------------------------------------------*
 *
 * Accepts a request from "sockid" and sends a response to "sockid".
 *
 *---------------------------------------------------------------------------*/

perform_http(int sockid)
{
	char fbuff[4096]; /*used to store the file content*/
	char content[4096];/*content of the file found*/
	char *path;/*path get from request*/
	int path_exist=0;// check if the path exists
	struct cli_addr; 
	int lenCli;
	int read_id=read(sockid,fbuff,sizeof(fbuff));
	if(read_id<0){
	 	perror("read error\n");
		exit(0);
	}
	if(read_id==0){
		perror("read nothing");
		exit(0);
	}
	char method[MAX_STR_LEN];
	char hostname[MAX_STR_LEN];
    	char file_path[MAX_STR_LEN];
    	char protocol[MAX_STR_LEN];
	
	if (sscanf(fbuff, "%s http://%[^/]%[^ ] %[^\n]", method, hostname, file_path,protocol) != 4) { 
		printf("get path fail");
		exit(0);
	
	}
	strcat(PATH,file_path);
	FILE* f = fopen(PATH, "r");
	if (strcmp(protocol, "HTTP/1.0\r") != 0){
		strcat(sent,HTTP_501);
    		close(sockid);

	}else{
        	if (f == NULL){
        		//file doesn't exist
            		strcat(sent,HTTP_404);
			close(sockid);
        	}else{
			strcat(sent,HTTP_200);
			path_exist=1;
			
		}
	}
    	time_t current_time;
	struct tm *mytime;
	time(&current_time);
	mytime=localtime(&current_time);
	strcat(sent,"Date: ");
	strcat(sent,asctime(mytime));
	char strTime[MAX_STR_LEN];
	strcat(sent, "Server: 10.10.1.100\r\n\r\n");
	if(path_exist==1){
		fseek(f, SEEK_SET, 0);
		fread(content, 4096, 1, f);
		//fscanf(f,"%s",content);
   		fclose(f);
		strcat(sent,content);
	}
	write(sockid,sent,4096);
	
}
















