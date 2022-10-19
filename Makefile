#
# Make file for the ISC TTDP test
#
CC = gcc
INCLUDE = -I.
CFLAGS +=  -g -O2 $(INCLUDE)

OBJS = open_sock.o
EXE = ttdp-test

all: $(EXE) 

$(EXE): $(OBJS) 
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clean:
	rm -f *.o  $(EXE) *~