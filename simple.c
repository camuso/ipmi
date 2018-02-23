/*
 * Watchdog Driver Test Program
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/watchdog.h>

int fd;

/*
 * The main program.  Run the program with "-d" to disable the card,
 * or "-e" to enable the card.
 */
int main(int argc, char *argv[])
{
	int time = 120;
	int option = WDIOS_ENABLECARD;
	struct watchdog_info	wdInfo;

	fd = open("/dev/watchdog", O_RDWR);

	if (fd == -1) {
		fprintf(stderr, "Watchdog device not enabled.\n");
		fflush(stderr);
		exit(-1);
	}

	if (ioctl(fd, WDIOC_SETTIMEOUT, &time ) < 0 )
		perror("SETTIMEOUT ioctl failed: ");

	printf("Timeout set for: %d seconds\n", time);
	printf("If I hang here, my ipmi_watchdog is buggy...\n");

	if (ioctl(fd, WDIOC_SETOPTIONS, &option) < 0 )
		perror("SETOPTIONS ioctl failed: ");

	printf("Woot, watchdog timer is enabled\n");

	close(fd);
	return 0;
}

