#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include "packet.h"


main(int argc, char **argv)
{
	struct sockaddr_in sin;	/* our address */
	struct sockaddr_in remaddr;	/* remote address */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # bytes received */
	int fd;				/* our socket */
	int msgcnt = 0;			/* count # of messages we received */
	unsigned char buf[PCKSIZE];	/* receive buffer */
	char* packet;			/* sending the ack packet */
	unsigned short server_port = atoi(argv[1]);


	/* create a UDP socket */

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket\n");
		return 0;
	}

	/* bind the socket to any valid IP address and a specific port */

	memset((char *)&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(server_port);

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind failed");
		return 0;
	}
	/* receive a ping packet and sent back a pong message */
	recvlen = recvfrom(fd, buf, PCKSIZE, 0, (struct sockaddr *)&remaddr, &addrlen);
	if (recvlen > 0) {
		buf[recvlen] = 0;
		if (sendto(fd, buf, 20, 0, (struct sockaddr *)&remaddr, addrlen) < 0)
			perror("sendto");
	}
 
	/* now loop, receiving data and printing what we received */
	FILE *fp = fopen("copy.txt", "w");
	printf("waiting on port %d\n", server_port);
	while(1) {
		recvlen = recvfrom(fd, buf, PCKSIZE, 0, (struct sockaddr *)&remaddr, &addrlen);
		printf("received length is %d\n",recvlen);
		if (recvlen > 0) {
			buf[recvlen] = 0;
			short type = (short) ntohs(*(short*)(buf));
			//printf("received message: \"%s\" (%d bytes)\n", buf+4, recvlen);

			/* if it is a ping packet */
			if(type == 0){					
				if (sendto(fd, buf, 20, 0, (struct sockaddr *)&remaddr, addrlen) < 0)
				perror("sendto");	
			} else if(type ==1){
			/* sending back acknowledgement*/ 
				short seq = (short) ntohs(*(short *)(buf+2));
				printf("The sequence number is %d\n",seq);
				
				packet = (char*)malloc(20*sizeof(char));
				*(short *) (packet) = (short) htons(seq);
				//sprintf(buf, "ack %d", msgcnt++);
				printf("sending ack %d\n", seq); 
				//printf("sending ack of size of %d\n",strlen(packet));
				if (sendto(fd, packet, 20, 0, (struct sockaddr *)&remaddr, addrlen) < 0)
					perror("sendto");
			}
		}
		else
			printf("uh oh - something went wrong!\n");
	}
	/* never exits */
}
