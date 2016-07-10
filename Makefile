pcap: pcap_sch.o
	gcc -o pcap pcap_sch.o -lpcap

pcap_sch.o: pcap_sch.c
	gcc -o pcap_sch.o -c pcap_sch.c

clean:
	rm -f *.o pcap_test
