#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include "packet.h"

#define SEQ_LENGTH 5000

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
	//append "0" bits until message length in bits กิ 448 (mod 512)
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

		// break chunk into sixteen 32-bit words w[j], 0 ก j ก 15
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

/* generate a ack packet including md5 */
char *generateAck(char* md5Ack, unsigned int AckNum){
	char* packet = (char*)malloc(18);
	memcpy(packet, md5Ack, 16);
	*((unsigned int *)packet + 16) = htons(AckNum);
	return packet;
}

/* get md5 from the receiving packet */
char *getMD5(char* packet){
	char* md5Packet = (char*)malloc(16);
	memcpy(md5Packet, packet, 16);
	return md5Packet;
}

/* check if the md5 from packet is the same as the generated one */
bool checkMD5(char *md5packet, char *md5result){
	int result = memcmp(md5packet, md5result, 16);
	return result == 0 ? true : false;
}

main(int argc, char **argv)
{
	int i;
	struct sockaddr_in sin;	/* our address */
	struct sockaddr_in remaddr;	/* remote address */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # bytes received */
	int fd;				/* our socket */
	int msgcnt = 0;			/* count # of messages we received */
	unsigned char buf[PCKSIZE];	/* receive buffer */
	char* packet;			/* sending the ack packet */
	unsigned short server_port = atoi(argv[1]);
	FILE *fp;			/* pointer to the destination file */

	char* content[SEQ_LENGTH];	/* The array to hold the received content buffer */
	int window[SEQ_LENGTH];	/* Receiver window size */
	int remaining_file_size = -1;	/* The number of bits remaining to be received */
	int remaining_packets;		/* The number of packets remaining to be sent */
	int last_seq;			/* The index of the last sequence number */
	/*
	* 0 if packet is not received
	* 1 if packet is received
	*/
	for (i = 0; i<SEQ_LENGTH; i++) {
		window[i] = 0;
	}

	for (i = 0; i<SEQ_LENGTH; i++) {
		content[i] = (char*)malloc(BUFLEN*sizeof(char));
	}

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

	char* checksum;
	char checkmd5[16];
	char md5ForAck[16];
	bool isRightData = false;

	/* now loop, receiving data and write the payload into a given file */
	printf("waiting on port %d\n", server_port);
	while (1) {
		recvlen = recvfrom(fd, buf, PCKSIZE, 0, (struct sockaddr *)&remaddr, &addrlen);
		printf("received length is %d\n", recvlen);
		if (recvlen > 0) {
			checksum = getMD5(buf);
			md5((uint8_t*)(buf + 16), recvlen - 16, (uint8_t*)checkmd5);
			isRightData = checkMD5(checksum, checkmd5);
			if (isRightData){
				buf[recvlen] = 0;
				short type = (short)ntohs(*(short*)(buf));

				/* if it is a ping pong message and it is the first time the receiver receive*/
				if (type == 0 && remaining_file_size == -1) {
					remaining_file_size = (int)ntohl(*(int*)(buf + 10));
					//remaining_packets = remaining_file_size/BUFLEN +1;
					last_seq = remaining_file_size / BUFLEN;
					fp = fopen("copy.txt", "w");
					if (sendto(fd, buf, 20, 0, (struct sockaddr *)&remaddr, addrlen) < 0)
						perror("sendto");
				}
				else { /* else it is a data packet */

					short seq_num = (short)ntohs(*(short*)(buf + 10));
					printf("The sequence number received is %d\n", seq_num);
					/* The packet with this sequence number has not been received */
					if (window[seq_num] != 1) {
						int file_buf_size = recvlen - 12 - 1; /* the received buffer size minus the headers' size */
						//printf("The size of the buffer is %d\n",file_buf_size);
						/*  Do not receives delayed packets after read in the last bit of the file */
						if (remaining_file_size >= file_buf_size) {
							remaining_file_size -= file_buf_size;
							//remaining_packets--;
							//printf("the remaining file size is %d\n",remaining_file_size);
							window[seq_num] = 1;
							strcpy(content[seq_num], buf + 12);
						}
					}

					/* sending back acknowledgement*/
					packet = (char*)malloc(20 * sizeof(char));
					int tv_sec = (int)ntohl(*(int*)(buf + 18));
					int tv_usec = (int)ntohl(*(int*)(buf + 22));
					*(short *)(packet + 16) = (short)htons(seq_num);
					*(int *)(packet + 18) = (int)htonl(tv_sec);
					*(int *)(packet + 22) = (int)htonl(tv_usec);
					md5((uint8_t*)(packet + 16), 10, (uint8_t*)md5ForAck);
					memcpy(packet, md5ForAck, 16);

					printf("sending ack %d\n", seq_num);
					if (sendto(fd, packet, 20, 0, (struct sockaddr *)&remaddr, addrlen) < 0)
						perror("sendto");
				}
			}
			else{
				printf("recv corrupt packet \n");
			}
		}
		else
			printf("uh oh - something went wrong!\n");


		/* check if all the packet in the window is received */
		int ready_flag = 1;
		for (i = 0; i<last_seq + 1; i++){
			if (window[i] == 0){
				ready_flag = 0;
				break;
			}
		}
		/* write to the file if all packets in one sliding window is received */
		if (ready_flag == 1){
			for (i = 0; i<last_seq + 1; i++){
				//	printf("The received content is %s\n",content[i]);
				printf("strlen is %d", strlen(content[i]) - 1);
				fwrite(content[i], 1, strlen(content[i]) - 1, fp);
				content[i] = (char*)malloc(BUFLEN*sizeof(char));
				window[i] = 0;
			}
			remaining_file_size = -1;
			fclose(fp);
		}
	}
	/* never exits */
}
// ./udp-send ring.clear.rice.edu 18000
