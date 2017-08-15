#makefile for project 1 works both in linux and unix system now

.c.o:
	gcc -g -c $?

# compile client and server
all: SimpClient SimpServer

# compile client only 
client: client.o 
	gcc -g -o SimpClient SimpClient.o   -lnsl

#compile server only
server: server.o 
	gcc -g -o SimpServer SimpServer.o   -lnsl
