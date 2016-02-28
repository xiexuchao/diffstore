CC = gcc 
CFLAGS = -g -Wall 

analyzer:analyzer.o initialize.o pool.o
	$(CC) analyzer.o initialize.o pool.o -o analyzer
analyzer.o:analyzer.c
	$(CC) $(CFLAGS) -c analyzer.c -o analyzer.o
initialize.o:initialize.c
	$(CC) $(CFLAGS) -c initialize.c -o initialize.o
pool.o:pool.c
	$(CC) $(CFLAGS) -c pool.c -o pool.o

.PHONY: clean
clean:
	rm -rf analyzer *.o
