#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>     /* for pause */
#include <signal.h>     /* for signal */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <iostream>
#include <errno.h>
#include "packet.h"

#define ALPHA 0.875  

/* using queue to handle the sequence of each timeout */
typedef struct {
	int first;                      /* position of first element */
	int last;                       /* position of last element */
	int count;                      /* number of queue elements */
	int q[100];			/* the body of queue */
} queue;
#include "queue.h"


struct alarm_time{
	int is_set;
	int tv_sec;
	int tv_usec;
	int duration;
};
struct alarm_time alarm_list[PCK_ROUND * 2];
#include "alarm.h"


void handle_alarm();

/* using queue to handle the sequence of each timeout */
queue* signal_queue;


int la_seq;		/* the least acknowledge sequence number */
int ns_seq;		/* the sequence number to be sent next */


int seq[PCK_ROUND * 2];	/* array of sequence number */
int retrans_signal[PCK_ROUND * 2];/* array that indicate packet retrasmission */
char* retrans_buffer[PCK_ROUND * 2];/* buffer that hold the packet to be retransmitted */

/* Simple MD5 implementation
*
* usage: call function md5(const uint8_t *msg, size_t length, uint8_t *result)
*        "result" should have at least 16 bytes space
*        then the first 16 bytes in result will be filled with the digest of msg
*/
// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

// r specifies the per-round shift amounts
const uint32_t r[] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void to_bytes(uint32_t val, uint8_t *bytes)
{
	bytes[0] = (uint8_t)val;
	bytes[1] = (uint8_t)(val >> 8);
	bytes[2] = (uint8_t)(val >> 16);
	bytes[3] = (uint8_t)(val >> 24);
}

uint32_t to_int32(const uint8_t *bytes)
{
	return (uint32_t)bytes[0]
		| ((uint32_t)bytes[1] << 8)
		| ((uint32_t)bytes[2] << 16)
		| ((uint32_t)bytes[3] << 24);
}

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {

	// These vars will contain the hash
	uint32_t h0, h1, h2, h3;

	// Message (to prepare)
	uint8_t *msg = NULL;

	size_t new_len, offset;
	uint32_t w[16];
	uint32_t a, b, c, d, i, f, g, temp;

	// Initialize variables - simple count in nibbles:
	h0 = 0x67452301;
	h1 = 0xefcdab89;
	h2 = 0x98badcfe;
	h3 = 0x10325476;

	//Pre-processing:
	//append "1" bit to message
	//append "0" bits until message length in bits ?? 448 (mod 512)
	//append length mod (2^64) to message

	for (new_len = initial_len + 1; new_len % (512 / 8) != 448 / 8; new_len++)
		;

	msg = (uint8_t*)malloc(new_len + 8);
	memcpy(msg, initial_msg, initial_len);
	msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
	for (offset = initial_len + 1; offset < new_len; offset++)
		msg[offset] = 0; // append "0" bits

	// append the len in bits at the end of the buffer.
	to_bytes(initial_len * 8, msg + new_len);
	// initial_len>>29 == initial_len*8>>32, but avoids overflow.
	to_bytes(initial_len >> 29, msg + new_len + 4);

	// Process the message in successive 512-bit chunks:
	//for each 512-bit chunk of message:
	for (offset = 0; offset<new_len; offset += (512 / 8)) {
		// break chunk into sixteen 32-bit words w[j], 0 ?? j ?? 15
		for (i = 0; i < 16; i++)
			w[i] = to_int32(msg + offset + i * 4);
		// Initialize hash value for this chunk:
		a = h0;
		b = h1;
		c = h2;
		d = h3;

		// Main loop:
		for (i = 0; i<64; i++) {
			if (i < 16) {
				f = (b & c) | ((~b) & d);
				g = i;
			}
			else if (i < 32) {
				f = (d & b) | ((~d) & c);
				g = (5 * i + 1) % 16;
			}
			else if (i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			}
			else {
				f = c ^ (b | (~d));
				g = (7 * i) % 16;
			}
			temp = d;
			d = c;
			c = b;
			b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
			a = temp;
		}

		// Add this chunk's hash to result so far:
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
	}
	// cleanup
	free(msg);

	//var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
	to_bytes(h0, digest);
	to_bytes(h1, digest + 4);
	to_bytes(h2, digest + 8);
	to_bytes(h3, digest + 12);
}

/* get md5 from receiving ack*/
char* getMD5ForAck(char *ackPacket){
	char* md5ForAck = (char *)malloc(16);
	memcpy(md5ForAck, ackPacket, 16);
	return md5ForAck;
}

int main(int argc, char** argv)
{
	struct sockaddr_in sin;
	int sock, i, slen = sizeof(sin);
	char buf[BUFLEN];	/* message buffer */
	char *file_buf, *packet;
	int recvlen;		/* # bytes in acknowledgement message */
	int rtt;		/* round trip time in millisecond */
	struct timeval tv;
	struct hostent *host = gethostbyname(argv[1]);

	signal_queue = (queue*)malloc(sizeof(queue)); /* initial queue for timeout signal generated by each transmission */

	/* 0: not used
	* 1: being transmitted, waiting for ack
	* 2: ack received
	*/
	for (i = 0; i<PCK_ROUND * 2; i++){
		seq[i] = 0;
	}
	/* 0: no need to retransmission
	* 1: need retransmission
	*/
	for (i = 0; i<PCK_ROUND * 2; i++){
		retrans_signal[i] = 0;
	}

	unsigned int server_addr = *(unsigned int *)host->h_addr_list[0];
	/* server port number */
	unsigned short server_port = atoi(argv[2]);

	/* create a socket */

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		printf("socket created\n");

	/* bind it to the server addresses and use the given port number */
	memset((char *)&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = server_addr;
	sin.sin_port = htons(server_port);

	FILE *fp = fopen("2.txt", "r");
	/* get the size of the file */
	fseek(fp, 0l, SEEK_END);
	int file_size = ftell(fp);
	rewind(fp);
	printf("The file size is %d\n", file_size);

	char checkSum1[16];
	char checkSum2[16];
	/* initial packet*/
	packet = (char*)malloc(PCKSIZE*sizeof(char));
	gettimeofday(&tv, NULL);
	/* send a ping-pong message to get the rtt */
	*(short *)(packet + 16) = (short)htons(0); /* 0 means it is a ping packet*/
	*(int *)(packet + 18) = (int)htonl(tv.tv_sec);
	*(int *)(packet + 22) = (int)htonl(tv.tv_usec);
	*(int *)(packet + 26) = (int)htonl(file_size);
	md5((uint8_t*)packet, strlen(packet), (uint8_t*)checkSum1);
	memcpy(packet, checkSum1, 16);

	printf("sending ping pong packet\n");
	if (sendto(sock, packet, PCKSIZE, 0, (struct sockaddr *)&sin, slen) == -1) {
		perror("ping packet sending failure\n");
		exit(1);
	}
	/* set timeout for ping pong packet */
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))<0){
		printf("socket option  SO_RCVTIMEO not support\n");
		return;
	}
	/* now receive a pong packet from the server */
	while (1) {
		recvlen = recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&sin, &slen);
		if (recvlen < 0) { /* timeout occurs, trigger a retransmission */
			printf("recvfrom timeout\n");
			gettimeofday(&tv, NULL);
			/* send a ping-pong message to get the rtt */
			*(short *)(packet + 16) = (short)htons(0); /* 0 means it is a ping packet*/
			*(int *)(packet + 18) = (int)htonl(tv.tv_sec);
			*(int *)(packet + 22) = (int)htonl(tv.tv_usec);
			*(int *)(packet + 26) = (int)htonl(file_size);
			md5((uint8_t*)packet, strlen(packet), (uint8_t*)checkSum2);
			memcpy(packet, checkSum2, 16);

			printf("sending ping pong packet\n");
			if (sendto(sock, packet, PCKSIZE, 0, (struct sockaddr *)&sin, slen) == -1) {
				perror("ping packet sending failure\n");
				exit(1);
			}
		}
		else if (recvlen >= 0) {

			buf[recvlen] = 0;	/* expect a printable string - terminate it */
			int tv_sec, tv_usec;
			tv_sec = (int)ntohl(*(int *)(buf + 2));
			tv_usec = (int)ntohl(*(int *)(buf + 6));

			gettimeofday(&tv, NULL);
			rtt = 1000000 * (tv.tv_sec - tv_sec) + (tv.tv_usec - tv_usec);
			break;
		}
	}

	printf("The RTT is %d\n", rtt);

	/* read file to a buffer with BUFLEN length and send it to the sever continuously*/
	packet = (char*)malloc(PCKSIZE*sizeof(char));
	file_buf = (char*)malloc(BUFLEN*sizeof(char));
	char checkSum3[16];
	char checkSum4[16];
	char checkSum5[16];
	if (fp != NULL) {

		i = 0;
		la_seq = ns_seq = 0;
		/* send PCK_ROUND number of packets at the first round */
		while (i<PCK_ROUND) {
			file_buf = (char*)malloc(BUFLEN*sizeof(char));
			size_t newLen = fread(file_buf, sizeof(char), BUFLEN, fp);
			if (newLen == 0) {
				break;
			}
			else {
				file_buf[++newLen] = '\0'; /* Just to be safe. */
				printf("sending packet with sequence number %d\n", ns_seq);
				//printf("The buffer contains:\n");
				//printf("%s\n\n",file_buf);

				gettimeofday(&tv, NULL);
				/* create the ftp packet */
				*(short *)(packet + 16) = (short)htons(1); /* 1 means it is a ftp packet */
				*(int *)(packet + 18) = (int)htonl(tv.tv_sec);
				*(int *)(packet + 22) = (int)htonl(tv.tv_usec);
				*(short *)(packet + 26) = (short)htons(ns_seq);
				strcpy(packet + 28, file_buf);
				md5((uint8_t*)packet, newLen + 12, (uint8_t*)checkSum3);
				memcpy(packet, checkSum3, 16);
				int pck_size = 28 + newLen;
				printf("packet size is %d\n", pck_size);
				if (sendto(sock, packet, pck_size, 0, (struct sockaddr *)&sin, slen) == -1) {
					perror("buffer sending failure\n");
					exit(1);
				}
				set_alarm(ns_seq, 1.5*rtt);
				seq[ns_seq] = 1;
				/* store the buffer for retransmission */
				retrans_buffer[ns_seq] = (char*)malloc(BUFLEN*sizeof(char));
				strcpy(retrans_buffer[ns_seq], file_buf);
				ns_seq = (ns_seq + 1) % (PCK_ROUND * 2);
				free(file_buf);
			}
			i++;
		}
		while (1) {

			check_expire(); /* check whether there are alarm expired */
			/*  Keep waiting for acknowledgements from the server */
			/*  Make the recvfrom non blocking to receive latter acknowledgements */
			recvlen = recvfrom(sock, packet, 20, MSG_DONTWAIT, (struct sockaddr *)&sin, &slen);
			//printf("received length is %d\n",recvlen);
			if (recvlen == 18) {
				packet[recvlen] = 0;
				short ack_num = (short)ntohs(*(short *)(packet));
				char *md5Ack = getMD5ForAck(packet);
				md5((uint8_t*)&ack_num, 2, (uint8_t*)checkSum3);
				if (memcmp(md5Ack, checkSum3, 16) == 0){
					printf("The acknowledge number is %d\n", ack_num);
					if (seq[ack_num] == 2) { /* this packet has already arrived */
						continue;
					}

					seq[ack_num] = 2; /* sequence number is acknowledged */

					/* update the rtt based on the new rtt */
					int tv_sec, tv_usec;
					tv_sec = (int)ntohl(*(int *)(buf + 18));
					tv_usec = (int)ntohl(*(int *)(buf + 22));

					gettimeofday(&tv, NULL);
					int newRtt = 1000000 * (tv.tv_sec - tv_sec) + (tv.tv_usec - tv_usec);
					rtt = ALPHA*rtt + (1 - ALPHA)*newRtt;

					int count = 0;
					if (ack_num == la_seq) {
						i = la_seq;
						while (seq[i] == 2) {
							seq[i] = 0; /*sliding windows moving right*/
							count++;
							i = (i + 1) % (PCK_ROUND * 2);

						}
						la_seq = (la_seq + count) % (PCK_ROUND * 2);
					}
					/* multiple packets accumulated to be sent */
					while (count != 0) {
						file_buf = (char*)malloc(BUFLEN*sizeof(char));
						size_t newLen = fread(file_buf, sizeof(char), BUFLEN, fp);
						if (newLen == 0) {
							break;
						}
						else {
							file_buf[++newLen] = '\0'; /* Just to be safe. */
							//printf("The buffer contains:\n");
							//printf("%s\n",file_buf);
							printf("sending packet with sequence number %d\n", ns_seq);

							gettimeofday(&tv, NULL);
							/* create the ftp packet */
							*(short *)(packet + 16) = (short)htons(1); /* 1 means it is a ftp packet */
							*(int *)(packet + 18) = (int)htonl(tv.tv_sec);
							*(int *)(packet + 22) = (int)htonl(tv.tv_usec);
							*(short *)(packet + 26) = (short)htons(ns_seq);
							strcpy(packet + 28, file_buf);
							md5((uint8_t*)packet, newLen + 12, (uint8_t*)checkSum4);
							memcpy(packet, checkSum4, 16);
							int pck_size = 28 + newLen;
							printf("packet size is %d\n", pck_size);
							if (sendto(sock, packet, pck_size, 0, (struct sockaddr *)&sin, slen) == -1) {
								perror("buffer sending failure\n");
								exit(1);
							}
							seq[ns_seq] = 1;
							set_alarm(ns_seq, 1.5*rtt);
							/* store the buffer for retransmission */
							retrans_buffer[ns_seq] = malloc(BUFLEN*sizeof(char));
							strcpy(retrans_buffer[ns_seq], file_buf);
							ns_seq = (ns_seq + 1) % (PCK_ROUND * 2);
							count--;
							free(file_buf);
						}
					}
				} // end of transmit new file
				else if (recvlen > 0 && recvlen != 18){
					printf("ack corrupt \n");
			}

			/* check for transmission packets */
			for (i = 0; i<PCK_ROUND * 2; i++) {
				if (retrans_signal[i] == 1 && seq[i] == 1) {
					retrans_signal[i] = 0;

					gettimeofday(&tv, NULL);
					/* create the ftp packet */
					packet = (char*)malloc(PCKSIZE*sizeof(char));
					*(short *)(packet + 16) = (short)htons(1); /* 1 means it is a ftp packet */
					*(int *)(packet + 18) = (int)htonl(tv.tv_sec);
					*(int *)(packet + 22) = (int)htonl(tv.tv_usec);
					*(short *)(packet + 26) = (short)htons(i);
					strcpy(packet + 28, retrans_buffer[i]);
					md5((uint8_t*)packet, strlen(retrans_buffer[i]) + 12, (uint8_t*)checkSum5);
					memcpy(packet, checkSum5, 16);
					printf("retransmitting packet with sequence number %d\n", i);
					int pck_size = 28 + strlen(retrans_buffer[i]);
					if (sendto(sock, packet, pck_size, 0, (struct sockaddr *)&sin, slen) == -1) {
						perror("buffer sending failure\n");
						exit(1);
					}
					set_alarm(i, 1.5*rtt);
					//seq[i] = 1;
				}
			}
		}
		fclose(fp);
	}

	close(sock);
	return 0;
}

/* id is the sequence number of a packet and duration is the length of the timeout */
void set_alarm(int id, int duration) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	alarm_list[id].is_set = 1;
	alarm_list[id].tv_sec = tv.tv_sec;
	alarm_list[id].tv_usec = tv.tv_usec;
	alarm_list[id].duration = duration;
}

/* iterate through all the packets being transmitted and check for timeout expires */
void check_expire() {
	int i;
	struct timeval tv;
	/* go through all the possible sequence number */
	for (i = 0; i<PCK_ROUND * 2; i++) {
		if (alarm_list[i].is_set == 1) {
			gettimeofday(&tv, NULL);
			int elapsed_time = (tv.tv_sec - alarm_list[i].tv_sec) * 1000000 + (tv.tv_usec - alarm_list[i].tv_usec);
			//printf("elapsed time is %d\n", elapsed_time);
			if (elapsed_time > alarm_list[i].duration) {
				alarm_list[i].is_set = 0;
				handle_alarm(i);
			}
		}
	}
}

void handle_alarm(int seq_num) {
	/* if the acknowledge is not received, perform a retransmission */
	if (seq[seq_num] == 1){
		/* set flag to indicate packet retransmission*/
		retrans_signal[seq_num] = 1;
	}
	printf("handling alarm\n");
}
