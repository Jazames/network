CC=g++
CFLAGS=-c -Wall -std=c++14  -g
LDFLAGS=-L./ -lpthread 

SOURCES=mainLab2.cpp frameio.cpp util.cpp arp_util.cpp
OBJECTS=$(SOURCES:.cpp=.o)
	EXECUTABLE=lab2

.PHONY: all clean

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) 

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)

