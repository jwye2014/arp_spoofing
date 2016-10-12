OBJECTS = arp_spoofing.o

TARGET = arp_spoof
$(TARGET) : $(OBJECTS)
	gcc -o $(TARGET) $(OBJECTS) -lpcap

arp_spoofing.o : arp_spoofing.c
