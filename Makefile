OBJECTS =  client server
TARGET = client server base64 getip fragmentation

all: $(OBJECTS)

clean:
	-rm -f *.o $(TARGET)
	-rm -f $(OBJECTS)

client: client.o getip.o base64.o fragmentation.o
	cc -o client client.o getip.o base64.o fragmentation.o

server: server.o getip.o base64.o fragmentation.o
	cc -o server server.o getip.o base64.o fragmentation.o

client.o: client.c
	cc -c client.c

server.o: server.c
	cc -c server.c

base64.o: base64.c
	cc -c base64.c

getip.o: getip.c
	cc -c getip.c

fragmentation.o: fragmentation.c
	cc -c fragmentation.c