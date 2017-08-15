
-------------------------explanation of files ----------------------
361ass2_test.c:combination of methods to process the trace file and computes summary information about TCP connections
Makefile: compile 361ass2_test.c
Readme.txt: instructions of how to use files in project2
sample-capture-file: trace file

------------------------------run code------------------------------

1. run make (compile 361ass2_test.c)

2. run ./361ass2_test <trace file name>
	for example, run ./361ass2_test sample-capture-file
	
	 
Note: maximum packet set in 361ass2_test.c is 2000, if the packet_length of used the trace file is more than 2000, then need to reset the MAX_NUM_PACKETS.
