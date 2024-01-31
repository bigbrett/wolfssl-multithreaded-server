CC=gcc
CFLAGS=-I. $(INCLUDES)
LIBS=-lwolfssl

WOLFSSL_INSTALL=$(shell pwd)/wolfssl-install

# Add your include paths here (e.g., -I/path/to/include)
INCLUDES=-I$(WOLFSSL_INSTALL)/include -I/home/brett/workspace/wolfssl/wolfssl-repos/wolfssl

# Add your library paths here (e.g., -L/path/to/lib)
LDFLAGS=-L$(WOLFSSL_INSTALL)/lib

# Add your libraries here (e.g., -lname)
LDLIBS=$(LIBS)

main: main.o
	$(CC) -o main main.o $(LDFLAGS) $(LDLIBS)

main.o: main.c
	$(CC) -c -g main.c $(CFLAGS)

clean:
	rm -f *.o main

run: main
	LD_LIBRARY_PATH=$(WOLFSSL_INSTALL)/lib ./main
