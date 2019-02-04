#
# File          : Makefile
# Description   : Build file for CSE543 project 1, applied cryptography
#                 


# Environment Setup
#LIBDIRS=-L. -L/usr/lib64/
LIBDIRS=-L. -L/usr/lib/
INCLUDES=-I. -I/usr/include/
CC=gcc 
#DEFINES=-DD1 -DD2 -DD3 -DD4 -DD5 -DD6
DEFINES=-DD1 -DD4 -DD6
CFLAGS=-O0 -c $(INCLUDES) $(DEFINES) -g -Wall -m32 -ffreestanding -fno-stack-protector
LINK=gcc -g
LDFLAGS=$(LIBDIRS) -m32 -ffreestanding
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=cse543-x3 \
	cse543-x3-server-29
CSE543P3LIB=cse543-p3lib
CSE543P3LIBOBJS=cse543-proto-p3.o \
		 cse543-network.o \
		 cse543-ssl.o \
		 formats/cse543-format-29.o \
		 cse543-util.o 
LIBS=-lcrypto -lm 

#
# Project Protections

p1 : $(TARGETS)

cse543-x3 : cse543-p1.o lib$(CSE543P3LIB).a
	$(LINK) $(LDFLAGS) cse543-p1.o $(LIBS) -l$(CSE543P3LIB) -o $@

cse543-x3-server-29 : cse543-p1.o lib$(CSE543P3LIB).a
	$(CC) $(CFLAGS) cse543-p1.c -DCSE543_PROTOCOL_SERVER -o cse543-p3-server.o 
	$(LINK) $(LDFLAGS) cse543-p3-server.o $(LIBS) -l$(CSE543P3LIB) -o $@
	cp cse543-x3-server-29 ./binaries/

lib$(CSE543P3LIB).a : $(CSE543P3LIBOBJS)
	$(AR) $@ $(CSE543P3LIBOBJS)
	$(RANLIB) $@

strn-attack: cse543-strncpy-attack.o cse543-util.o
	$(LINK) $(LDFLAGS) cse543-strncpy-attack.o cse543-util.o -o $@

clean:
	rm -f *.o *~ $(TARGETS) lib$(CSE543CRLIB).a

BASENAME=p3-strn
tar: 
	tar cvfz $(BASENAME)-29.tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/cse543-p1.c \
            $(BASENAME)/cse543-strncpy-attack.c \
	    $(BASENAME)/binaries/cse543-x3-server-29 \
	    $(BASENAME)/formats/cse543-format-29.c \
	    $(BASENAME)/formats/cse543-format-29.h \
	    $(BASENAME)/cse543-proto-p3.c \
	    $(BASENAME)/cse543-proto.h \
	    $(BASENAME)/cse543-network.c \
	    $(BASENAME)/cse543-network.h \
	    $(BASENAME)/cse543-ssl.c \
	    $(BASENAME)/cse543-ssl.h \
	    $(BASENAME)/cse543-util.c \
	    $(BASENAME)/cse543-util.h 

