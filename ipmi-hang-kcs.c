#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/io.h>

#define KCS_DATA_PORT 0xc80

unsigned long range_us = 1000000;  	// 1 second
unsigned long min_us = 1000000;  	// 1 second

main()
{
	int kcs_byte;
	int seqno = 0;
	int sleeptime;

	printf("\nipmi kcs hang test\n\n");

	// we need privileges to read the i/o port
	//
	iopl(3);

	for (;;) {
		++seqno;
		kcs_byte = inb(KCS_DATA_PORT);
		printf("%03d kcs_byte: %02x ", seqno, kcs_byte);

		// sleep between 1 and 2 seconds
		//
		sleeptime = min_us + random() % range_us;
		printf(" Wait Time: %d\n", sleeptime);
		usleep(sleeptime);
	}
}

