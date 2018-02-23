#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <linux/ipmi.h>
#include <netinet/in.h>
#include <net/if.h>
#include <signal.h>

#define uchar		unsigned char
#define EXIT_SUCCESS	0
#define EXIT_FAIL	1
#define EXIT_USAGEERR	2
#define DMIDECODE	"/usr/sbin/dmidecode"
#define IPMI_DRIVER	"/dev/ipmi0"

typedef	enum {
	UNKNOWN = 0,
	X86HOST,
} product_t;

typedef struct {
        int rack;
        int subrack;
        int slot;
} HWlocation;

#define _X86HOST			"X86HOST"

// Global Variables
int		Verbose;
product_t	product;
char		productid[32];
char		toolname[32];

void sigTermHandler(int sigNum) {
	if (sigNum != SIGTERM)
	{
		// Ignore SIGTERM signal only.
		fprintf(stderr, 
			"%s: Error: Received signal %d, terminating...\n",
			toolname,sigNum);
		exit(EXIT_FAIL);
	}
	else
	{
		signal(SIGTERM, SIG_DFL);
	}
	return;
}
 
int
setipmbaddr ( uchar ipmbaddr )
{
	int		rc;
	int		fd;
	struct ipmi_channel_lun_address_set	sChan;

	/*
	 *  IPMI allows multiple IPMB channels on a single interface, and
	 *  each channel might have a different IPMB address.  However, the
	 *  driver has only one IPMB address that it uses for everything.
	 *  This procedure adds new IOCTLS and a new internal interface for
	 *  setting per-channel IPMB addresses and LUNs.
	 */
	// open IPMI driver
	if ( (fd = open( IPMI_DRIVER, O_RDWR )) < 0 )
	{
		fprintf( stderr,
			"%s: Error: No device %s or IPMI driver not loaded\n",
			toolname,IPMI_DRIVER);
		return -1;
	}

	// find what it was set to
	sChan.channel = 0;
	sChan.value   = 0;
	rc = ioctl( fd, IPMICTL_GET_MY_CHANNEL_ADDRESS_CMD, &sChan );
	if ( rc < 0 )
	{
		fprintf( stderr,
			"%s: Error: IPMICTL_GET_MY_CHANNEL_ADDRESS_CMD "
			"ioctl_rc=%d errno=%d\n", toolname, rc, errno );
		close( fd );
		return -1;
	}
	if ( Verbose )
	{
		printf( "check default ADDRESS: channel = %d, addr = 0x%02X\n",
			sChan.channel, sChan.value );
	}

	// set it to the new value
	sChan.value = ipmbaddr;
	rc = ioctl( fd, IPMICTL_SET_MY_CHANNEL_ADDRESS_CMD, &sChan );
	if ( rc < 0 )
	{
		fprintf(stderr, "%s: Error: IPMICTL_SET_MY_CHANNEL_ADDRESS_CMD "
			"ioctl_rc=%d errno=%d\n", toolname, rc, errno );
		close( fd );
		return -1;
	}
	if ( Verbose )
	{
		printf( "default ADDRESS changed channel = %d addr = 0x%02X\n",
			sChan.channel, sChan.value );
	}

	// double check the setting
	rc = ioctl( fd, IPMICTL_GET_MY_CHANNEL_ADDRESS_CMD, &sChan );
	if ( rc < 0 )
	{
		fprintf( stderr, "%s: Error: IPMICTL_GET_MY_CHANNEL_ADDRESS_CMD"
			" ioctl_rc=%d errno=%d\n", toolname, rc, errno );
		close( fd );
		return -1;
	}
	if ( Verbose )
	{
		printf( "new default ADDRESS: channel = %d, addr = 0x%02X\n",
			sChan.channel, sChan.value );
	}

	if ( sChan.value != ipmbaddr )
	{
		fprintf( stderr, "%s: Error: Setting new address failed "
			"value = 0x%02X addr = 0x%02X\n",
			toolname, sChan.value, ipmbaddr );
		close( fd );
		return -1;
	}

	close( fd );
	return 0;

} // end of setipmbaddr()

int
ipmicmd_mv ( int addr_type, uchar cmd, uchar netfn, uchar lun,
	     uchar *pdata, uchar sdata, uchar *presp, int sresp, int *rlen )

{
	/*
	 * 
	 * It opens the IPMI driver, formats an IPMI command for the
	 * specified address type, and then sends it to IPMI. It waits
	 * for a response and then updates *presp with the results.
	 */

	int		ipmi_fd;
	fd_set		readfds;
	int		rv;
	char		*endptr;
	struct timeval	tv;

	struct ipmi_recv	rsp;
	struct ipmi_addr	addr;
	struct ipmi_req		req;
	struct ipmi_ipmb_addr	ipmb_addr;
	struct ipmi_system_interface_addr	bmc_addr;

	static int	curr_seq = 0;

	*rlen = 0;

	// open IPMI driver
	if ( (ipmi_fd = open( IPMI_DRIVER, O_RDWR )) < 0 )
	{
		fprintf( stderr,
			"%s: Error: No device %s or IPMI driver not loaded\n",
			toolname, IPMI_DRIVER);
		return -1;
	}

	FD_ZERO( &readfds );
	FD_SET( ipmi_fd, &readfds );

	/*
	 *  Send the IPMI command 
	 */
	switch (addr_type) {
	case IPMI_IPMB_ADDR_TYPE:
		ipmb_addr.addr_type  = IPMI_IPMB_ADDR_TYPE;
		ipmb_addr.slave_addr = IPMI_BMC_SLAVE_ADDR;
		ipmb_addr.channel    = 0x00;
		ipmb_addr.lun        = lun;
		req.addr     = (char *) &ipmb_addr;
		req.addr_len = sizeof(ipmb_addr);
		break;

	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
		bmc_addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
		bmc_addr.channel   = IPMI_BMC_CHANNEL;
		bmc_addr.lun       = lun;	// BMC_LUN = 0
		req.addr     = (char *) &bmc_addr;
		req.addr_len = sizeof(bmc_addr);
		break;

	default:
		fprintf( stderr, "%s: Error: Unknown addressing type %d\n",
			toolname, addr_type );
		close( ipmi_fd );
		return -1;
	}

	req.msg.cmd	 = cmd;
	req.msg.netfn	 = netfn;
	req.msgid	 = curr_seq++;
	req.msg.data	 = pdata;
	req.msg.data_len = sdata;
	if ( (rv = ioctl( ipmi_fd, IPMICTL_SEND_COMMAND, &req )) < 0 )
	{
		fprintf( stderr,
			"%s: Error: IPMICTL_SEND_COMMAND "
			"ioctl_rc=%d errno=%d\n", toolname, rv, errno );
		close( ipmi_fd );
		return -1;
	}

	/*
	 *  Wait for response
	 */
	int dataToRead = 0;
	int counter;
	for ( counter = 0; counter < 3 && !dataToRead; counter++ )
	{
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		rv = select( ipmi_fd+1, &readfds, NULL, NULL, &tv );
		if ( rv && FD_ISSET( ipmi_fd, &readfds ) )
	    		dataToRead = 1;
	}
	if ( !dataToRead  )
	{
		if ( Verbose )
		{
			fprintf( stderr, "%s: Error: No response from IPMI\n",
				toolname);
		}
		close( ipmi_fd );
		return -1;
	}

	/*
	 *  Receive the IPMI response
	 */
	rsp.addr	 = (char *) &addr;
	rsp.addr_len	 = sizeof(addr);
	rsp.msg.data	 = presp;
	rsp.msg.data_len = sresp;
	if ( (rv = ioctl( ipmi_fd, IPMICTL_RECEIVE_MSG_TRUNC, &rsp )) < 0 )
	{
		fprintf( stderr,
			"%s: Error: IPMICTL_RECEIVE_MSG_TRUNC "
			"ioctl_rc=%d errno=%d\n", toolname, rv, errno );
		close( ipmi_fd );
		return -1;
	}

	*rlen = rsp.msg.data_len;
	close( ipmi_fd );
	return 0;

} // end of ipmicmd_mv()

int
run_dmidecode ( char *dmi_option )
{
	struct timeval	tv;
	FILE* fp;
	fd_set readfds;
	int dmid_fd;
	int rc = 0;
	int rv = 0;
	int dataToRead = 0;
	int counter = 0;

	char cmd[ 256 ];

	// productid is a global set by this function
	memset( productid, 0, sizeof(productid) );

	// Allow parent to ignore SIGTERM.	
	signal(SIGTERM, sigTermHandler);

	sprintf( cmd, "%s -s %s", DMIDECODE, dmi_option );

	fp = popen( cmd, "r" );
	if ( fp == NULL )
	{
		fprintf( stderr, "%s: Error: popen of '%s' failed\n",
			toolname, cmd);
		return -1;
	}
	else
	{
		dmid_fd = fileno(fp);
		FD_ZERO(&readfds);
		FD_SET(dmid_fd,&readfds);

		/*
		 *  Wait for response
		 */
		dataToRead = 0;
		for ( counter = 0; counter < 3 && !dataToRead; counter++ )
		{
		    tv.tv_sec=4;
		    tv.tv_usec=0;
		    rv = select(dmid_fd+1, &readfds, NULL, NULL, &tv);
		    if ( rv && FD_ISSET( dmid_fd, &readfds ) )
         		dataToRead = 1;
		}
		if ( !dataToRead )
		{
			fprintf(stderr, "%s: Error: '%s' timed out.\n",
				toolname, cmd);
			close( dmid_fd);
			// kill child process created by popen()
			// sigTermHandler prevents parent from being
			// killed before error messages are sent.
			rc = killpg(0,SIGTERM);
			if (rc != 0)
			{
		    		fprintf(stderr, 
		    			"%s: Error: could not TERMinate "
		    			"sub-process\n",toolname);
			}
			return -1;
		}

		fgets( productid, sizeof(productid)-1, fp);
	}

	rc = pclose( fp );
	if (rc != 0)
	{
	    if (rc == -1)
	    {
		fprintf( stderr,
			"%s: Error: getting productid rc=%d, errno %d (%s).\n",
			toolname, rc, errno, strerror(errno));
	    }
	    else
	    {
		fprintf( stderr, "%s: Error: '%s' failed (rc=%d)\n",
			toolname, cmd, rc);
	    }
	    return -1;
	}
	return 0;
} // end of run_dmidecode()

int
detect_hardware ( char *arg )
{
	if ( arg == NULL )
	{
		// no argument, then attempt to discover hardware
		if ( run_dmidecode("baseboard-product-name") )
		{
			// dmidecode failed
			exit(EXIT_FAIL);
		}

		if ( strlen(productid) == 0 )
		{
			// check a different BIOS setting
			if ( run_dmidecode("system-product-name") )
			{
				// dmidecode failed
				exit(EXIT_FAIL);
			}

			if ( strlen(productid) == 0 )
			{
				fprintf( stderr, "%s: Error: setting productid\n",toolname);
				return -1;
			}
		}
	}
	else
	{
		// get product ID from argument
		strncpy( productid, arg, sizeof(productid)-1 );
	}

	product = UNKNOWN;

	if ( !strncmp( productid, _X86HOST, strlen(_X86HOST) ) )
	{
		product = X86HOST;
	}
	else
	{
		fprintf( stderr, "%s: Error: unsupported productid '%s'\n",toolname,productid);
		return -1;
	}
	return 0;
} // end of detect_hardware()



#define MAX_STA		8

static int	conv_slot[ MAX_STA*2 ] = {  0,  7,  8,  6,  9,  5, 10,  4,
					       11,  3, 12,  2, 13,  1, 14 };


int
read_address (HWlocation *hwdata)
{
	char		rsp_data[40];
	char		data[40];
	int		rc, subr;
	int		rlen;
	int		fd;
	int		mode;
	int		i;
	int		logical_slot;
	char		line[200];
	FILE*		fp;
	uchar		ipmbaddr;

	// Initialize
	hwdata->rack = 0;
	hwdata->subrack = 0;
	hwdata->slot = 0;
	logical_slot = 0;

	switch ( product ) 
	{
	case X86HOST:

		memset( data, 0, sizeof(data) );
		memset( rsp_data, 0, sizeof(rsp_data) );
		rc = ipmicmd_mv( IPMI_SYSTEM_INTERFACE_ADDR_TYPE,
				 0x01, 0x2c, 0, data, 1,
				 rsp_data, sizeof(rsp_data), &rlen );

		if ( rc < 0 || rlen < 4 )
		{
			fprintf( stderr,
				"%s: Error: in ipmicmd_mv get address info "
				"rc=%d rlen=%d\n", toolname, rc, rlen );
			return -1;
		}
		if ( rsp_data[0] != 0 )
		{
			fprintf( stderr, "%s: Error: in get address info "
				"completion code 0x%2.2X\n",
				toolname, rsp_data[0] & 0xff);
			return -1;
		}

		if ( Verbose )
		{
			int i = 0;
			printf("Logical address query\n");
			for (i = 0; i < rlen; i++) {
				printf("rsp_data[%i]  %02X\n", i, rsp_data[i]);
			}
		}

		/* Store logical slot */
		logical_slot = rsp_data[2] & 0x0F;

		// set IPMB address
		ipmbaddr = rsp_data[3];
		rc = setipmbaddr( ipmbaddr );
		if ( rc < 0 )
		{
			fprintf( stderr,
				"%s: Error: in setipmbaddr rc=%d ipmbaddr=%d\n",
				toolname, rc, ipmbaddr);
			return -1;
		}		

		/*
		 * This code queries the physical slot of a card given
		 * the IPMB address.
		 */
		memset( data, 0, sizeof(data) );
		memset( rsp_data, 0, sizeof(rsp_data) );

		/* Copying IPMB address. data 0 & 1 should be 0 */
		data[2] = 1;
		data[3] = ipmbaddr & 0xff ;
		rc = ipmicmd_mv( IPMI_IPMB_ADDR_TYPE,
				 0x01, 0x2c, 0, data, 4,
				 rsp_data, sizeof(rsp_data), &rlen );

		if ( rc < 0 || rlen < 4 )
		{
			fprintf( stderr,
				"%s: Error: in ipmicmd_mv get address "
				"info rc=%d rlen=%d\n", toolname, rc, rlen );
			return -1;
		}
		if ( rsp_data[0] != 0 )
		{
			fprintf( stderr,
				"%s: Error: in get address info completion "
				"code 0x%2.2X\n", toolname, rsp_data[0] & 0xff);
			return -1;
		}

		if ( Verbose )
		{
			int i = 0;
			printf("Physical address query\n");
			for (i = 0; i < rlen; i++) {
				printf("rsp_data[%i]  %02X\n", i, rsp_data[i]);
			}
		}

		/* Physical slot */
		hwdata->slot = rsp_data[6] & 0x0F;

		/* If slot was not retrieved, then use logical slot */
		if (hwdata->slot == 0)
		{
			if ( Verbose )
			{
				printf("Failed to retrieve physical slot.\n");
				printf("Using table for conversion.\n");
			}
			hwdata->slot = conv_slot[ logical_slot & 0x0F ];
		}

		memset( rsp_data, 0, sizeof(rsp_data) );
		rc = ipmicmd_mv( IPMI_SYSTEM_INTERFACE_ADDR_TYPE,
				 0x01, 0x06, 0, NULL, 0,
				 rsp_data, sizeof(rsp_data), &rlen );

		if ( rc < 0 || rlen < 1 )
		{
			fprintf( stderr,
				"%s: Error: in ipmicmd_mv get device Id, "
				"rc=%d, rlen =%d\n",toolname,rc,rlen );
			return -1;
		}
		if ( rsp_data[0] != 0 )
		{
			fprintf( stderr, 
				"%s: Error: Get device Id error, completion "
				"code 0x%2.2X\n", 
				toolname, rsp_data[0] & 0xff );
			return -1;
		}

		if ( Verbose )
		{
			printf( "Device infos    ID  Rev Firmware  IPMI    PRODUCT\n" );
			printf( "-------------------------------------------------\n" );
			printf( "%s  %02X   %02X   %02X.%02X    %01X.%01X    %-30s\n",
				"              ",
				rsp_data[1], rsp_data[2] & 0xff, rsp_data[3],
				rsp_data[4] & 0xff, rsp_data[5] & 0x0f,
				(rsp_data[5] & 0xf0) >> 4,
				productid );
		}

		memset( rsp_data, 0, sizeof(rsp_data) );

		/*
		 * Get receive message queue interrupt via the BMC global enable register.
		 */
		rc = ipmicmd_mv( IPMI_SYSTEM_INTERFACE_ADDR_TYPE,
				 0x2f, 0x06, 0, NULL, 0,
				 rsp_data, sizeof(rsp_data), &rlen );

		if ( rc < 0 || rlen < 1 )
		{
			fprintf( stderr,
				"%s: Error: in ipmicmd_mv set BMC global "
				"enable, rc=%d, rlen =%d\n",
				toolname,rc,rlen );
			return -1;
		}
		if ( rsp_data[0] != 0 )
		{
			fprintf( stderr,
				"%s: Error: Set BMC global enable, completion"
				" code 0x%2.2X\n",
				toolname, rsp_data[0] & 0xff );
			return -1;
		}

		if ( Verbose )
		{
			printf ("Receive message queue interrupt is 0x%x\n",
				rsp_data[1] );
		}

		/*
		 * If not already set, set receive message queue interrupt via
		 * the BMC global enable register.
		 */
		if( rsp_data[1] == 0 )
		{
			memset( rsp_data, 0, sizeof(rsp_data) );
			memset( data, 0, sizeof(data) );
			data[0] = 0x1;

			if ( Verbose )
			{
				printf ("Setting receive message queue "
					"interrupt to 0x%x\n", data[0] );
			}

			/*
			 * Set receive message queue interrupt via the BMC
			 * global enable register.
			 */
			rc = ipmicmd_mv( IPMI_SYSTEM_INTERFACE_ADDR_TYPE,
					 0x2e, 0x06, 0, data, 1,
					 rsp_data, sizeof(rsp_data), &rlen );

			if ( rc < 0 || rlen < 1 )
			{
				fprintf( stderr,
					"%s: Error: in ipmicmd_mv set BMC "
					"global enable, rc=%d, rlen =%d\n",
					toolname,rc,rlen );
				return -1;
			}
			if ( rsp_data[0] != 0 )
			{
				fprintf( stderr,
					"%s: Error: Set BMC global enable, "
					"completion code 0x%2.2X\n",
					toolname, rsp_data[0] & 0xff );
				return -1;
			}
		}

		memset( data, 0, sizeof(data) );
		memset( rsp_data, 0, sizeof(rsp_data) );

		rc = ipmicmd_mv( IPMI_IPMB_ADDR_TYPE,
				 0x02, 0x2c, 0, data, 1,
				 rsp_data, sizeof(rsp_data), &rlen );

		if ( rc < 0 || rlen < 3 )
		{
			fprintf( stderr,
				"%s: Error: in ipmicmd_mv get chassis number"
				" Id, rc=%d, rlen =%d\n",toolname,rc,rlen );
			return -1;
		}
		if ( rsp_data[0] != 0 )
		{
			fprintf( stderr,
				"%s: Error: in get chassis number completion "
				"code 0x%2.2X\n", toolname, rsp_data[0]&0xFF );
			return -1;
		}
			  
		if ( Verbose )
		{
			printf( "\nIPMI Reponse rc=%d rlen=%d rsp_data[3]=0x%x "
				"rsp_data[7]=0x%x\n\n", 
				rc, rlen,rsp_data[3],rsp_data[7]);
		}

		// Populate chassis and cabinet number
		hwdata->subrack = rsp_data[3]&0xf;
		hwdata->rack = rsp_data[7]&0xf;

		if ( Verbose )
		{
			printf ("Maps to:  Cabinet    Chassis    Slot\n");
			printf ("-------------------------------------\n");
			printf( "          %02d         %01d         %02d\n",
				hwdata->rack,  hwdata->subrack, hwdata->slot );
		}
		break;

	default:

		printf("%s: Error: Unknown product '%s' !!\n", 
			toolname,productid);
		return -1;
	}

	if ((hwdata->rack < 0 ) || (hwdata->subrack < 0) || (hwdata->slot < 1 ))
	{
		printf("%s: Error: read_address found data out of range\n",
			toolname);
		printf("\t(slot expected to be > 0:"
			" rack= %d, subrack= %d, slot= %d)\n",
			hwdata->rack,hwdata->subrack,hwdata->slot);
		return -1;
	}

	return 0;

} // end of read_address()

void
usage()
{
	printf( "USAGE: getInfoIPMI -b|-c|-s [-v]\n\n" );
	printf( "        -v                      : verbose mode\n" );
	printf( "        -b                      : display cabinet\n" );
	printf( "        -c                      : display chassis\n" );
	printf( "        -s                      : display slot\n" );
	exit(EXIT_USAGEERR);

} // end of usage()

int
main ( int argc, char **argv )
{
	HWlocation hwdata;
	Verbose = 0; 
	int opt_b = 0;	// display cabinet
	int opt_c = 0;	// display chassis
	int opt_s = 0; 	// display slot
	int rc = 0;

	strncpy(toolname,argv[0],sizeof(toolname)-1);
	toolname[sizeof(toolname)-1] = 0;

	// process arguments
	argc--; argv++;
	while ( argc > 0 && argv[0][0] == '-' )
	{
		switch ( argv[0][1] ) {
		case 'b' :
			opt_b = 1;
			break;
		case 'c' :
			opt_c = 1;
			break;
		case 's' :
			opt_s = 1;
			break;
		case 'v' :
			Verbose = 1;
			break;
		default  :
			printf( "Unknown option %s\n", argv[0] );
			usage();
		}
		argc--; argv++;
	}

	if ((opt_s == 0) && (opt_c == 0) && (opt_b == 0))
	{
		usage();
	}

	// detect installed hardware
	if ( detect_hardware( argv[0] ) )
	{
		// hardware detection has failed
		printf("%s: Error: in detect_hardware\n",toolname);
		exit(EXIT_FAIL);
	}

	// read hardware information
	rc = read_address(&hwdata);
	if ( rc != 0 )
	{
		// failed to read address
		fprintf( stderr,
			"%s: Error: Unable to determine slot location.\n",
			toolname );
		exit(EXIT_FAIL);
	}

	if (opt_b == 1 )
	{
		printf("CABINETID=%d\n",hwdata.rack);
	}
	if (opt_c == 1 )
	{
		printf("CHASSISID=%d\n",hwdata.subrack);
	}
	if (opt_s == 1)
	{
		printf("SLOTID=%d\n",hwdata.slot);
	}

	exit(EXIT_SUCCESS);

} // end of main()
