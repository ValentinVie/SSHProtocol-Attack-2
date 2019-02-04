#
# File          : Makefile
# Description   : Build file for CSE543 project 1, applied cryptography
#                 


# Environment Setup
#LIBDIRS=-L. -L/usr/lib64/
LIBDIRS=-L. -L/usr/lib/
INCLUDES=-I. -I/usr/include/
CC=gcc 
#DEFINES=-DD1 -DD2 -DD3 -DD4 -DD5
DEFINES=-DD1 -DD3 -DD4 -DD5
CFLAGS=-c $(INCLUDES) $(DEFINES) -g -Wall -m32 -ffreestanding -fno-stack-protector
LINK=gcc -g
LDFLAGS=$(LIBDIRS) -m32 -ffreestanding
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=cse543-x2 \
	cse543-x2-server-29 
CSE543CRLIB=cse543-crlib
CSE543CRLIBOBJS=cse543-proto.o \
		 cse543-network.o \
		 cse543-ssl.o \
		 cse543-util.o \
		 formats/cse543-format-29.o 
LIBS=-lcrypto -lm 

#
# Project Protections

p1 : $(TARGETS)

cse543-x2 : cse543-p1.o lib$(CSE543CRLIB).a
	$(LINK) $(LDFLAGS) cse543-p1.o $(LIBS) -l$(CSE543CRLIB) -o $@

cse543-x2-server-29 : cse543-p1.o lib$(CSE543CRLIB).a
	$(CC) $(CFLAGS) cse543-p1.c -DCSE543_PROTOCOL_SERVER -o cse543-p1-server.o 
	$(LINK) $(LDFLAGS) cse543-p1-server.o $(LIBS) -l$(CSE543CRLIB) -o $@
	cp cse543-x2-server-29 binaries/

lib$(CSE543CRLIB).a : $(CSE543CRLIBOBJS)
	$(AR) $@ $(CSE543CRLIBOBJS)
	$(RANLIB) $@

heap-attack: cse543-heap-attack.o cse543-util.o
	$(LINK) $(LDFLAGS) cse543-heap-attack.o cse543-util.o -o $@

clean:
	rm -f *.o *~ $(TARGETS) lib$(CSE543CRLIB).a

BASENAME=p3-heap
tar: 
	tar cvfz $(BASENAME)-29.tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/cse543-p1.c \
	    $(BASENAME)/formats/cse543-format-29.h \
	    $(BASENAME)/formats/cse543-format-29.c \
	    $(BASENAME)/binaries/cse543-x2-server-29 \
	    $(BASENAME)/cse543-heap-attack.c \
	    $(BASENAME)/cse543-proto.c \
	    $(BASENAME)/cse543-proto.h \
	    $(BASENAME)/cse543-network.c \
	    $(BASENAME)/cse543-network.h \
	    $(BASENAME)/cse543-ssl.c \
	    $(BASENAME)/cse543-ssl.h \
	    $(BASENAME)/cse543-util.c \
	    $(BASENAME)/cse543-util.h 

