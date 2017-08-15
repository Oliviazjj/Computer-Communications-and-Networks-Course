
-------------------------explanation of files ----------------------
SimpClient.c: client side
SimpServer.c: server side
makefile: compile SimpServer.c and SimpClient.c
Readme.txt: instructions of how to use files in project1
web: folder to store a html file: index.html
index.html: a html file to test iif server and client are connected
------------------------------run code------------------------------

1. run make (compile both server and client codes)
If the purpose is to get the information of the existing website, go to step 2
if the purpose is to test if the client and server are connected, go to step 3
2. run ./SimpClient <url>
	url of the website must start with http://
	for example, run ./SimpClient http://www.cs.uvic.ca/index.html,
	to enter CS department website
	 
3.a.test Server and make sure index.html is in a folder named web
  	and run ./SimpServer portNumber nameOfdirectory 
  	e.g. run ./SimpServer 8080 web/
  b.open another terminal and run 
	./SimpClient http://10.10.1.100:[port number]/index.html 
	AND make sure the port number here is the same as the port number in step a
	for example, run ./SimpClient http://10.10.1.100:8080/index.html
  
