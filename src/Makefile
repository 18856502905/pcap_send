CC = gcc
SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)

INCLUDES = -I$(LIB_PATH)/libpcap/include
LIBPATH = -L$(LIB_PATH)/libpcap/lib

CFLAGS = -g -O2

LIBS = -Wl,-Bstatic -lpcap -Wl,-Bdynamic -ldl -lpthread -lm -lstdc++

.SUFFIXES: .C .o .h .hh .cc .cpp .c

.cc.o:
	$(CC) $(CCFLAGS) $(INCLUDES) -c -o $@ $<

.cpp.o:
	$(CC) $(CCFLAGS) $(INCLUDES) -c -o $@ $<

.c.o:
	$(CC) $(CCFLAGS) $(INCLUDES) -c -o $@ $<

default: obj

EXE = $(SEND_PATH)/bin/pcap_send
ALLOBJS = $(wildcard $(SEND_PATH)/src/*.o)

link:
	$(CC) -o $(EXE) $(ALLOBJS) $(LIBPATH) $(LIBS)
	
obj : $(OBJS)
	
# if we have SUBDIRS







