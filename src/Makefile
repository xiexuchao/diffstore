CC = gcc 
CFLAGS = -g -Wall 

analyzer:analyzer.o initialize.o pool.o seq_detector.o
	$(CC) analyzer.o initialize.o pool.o seq_detector.o -o analyzer
analyzer.o:analyzer.c
	$(CC) $(CFLAGS) -c analyzer.c -o analyzer.o
initialize.o:configure.c
	$(CC) $(CFLAGS) -c configure.c -o initialize.o
pool.o:pool.c
	$(CC) $(CFLAGS) -c pool.c -o pool.o
detector.o:seq_detector.c
	$(CC) $(CFLAGS) -c seq_detector.c -o seq_detector.o

.PHONY: clean
clean:
	rm -rf analyzer *.o
