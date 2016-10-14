#include <iostream.h>
//#include<stdio.h>
#include <stdlib.h>
#include <errno.h>		// defines perror(), herror() 
#include <fcntl.h>		// set socket to non-blocking with fcntrl()
#include <unistd.h>
#include <string.h>
#include <assert.h>		//add diagnostics to a program

#include <netinet/in.h>		//defines in_addr and sockaddr_in structures
#include <arpa/inet.h>		//external definitions for inet functions
#include <netdb.h>		//getaddrinfo() & gethostbyname()

#include <sys/socket.h>		//
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/select.h>		// for select() system call only
#include <sys/time.h>   // time() & clock_gettime()
#include <stdarg.h>
#include<ctype.h>

//define the sbcp structure
struct sbcp_message
{
uint16_t vrsn;
uint8_t  type;
uint16_t length;
uint16_t attr_type;
uint16_t attr_length;
const char *buffer;
};//structure done

char username[16];
char send_msg[508];

/*
** packi16() -- store a 16-bit int into a char buffer (like htons())
*/
void packi16(unsigned char *buf, uint16_t i)
{
    *buf++ = i>>8; 
    *buf++ = i;
}

/*
** unpacki16() -- unpack a 16-bit int from a char buffer (like ntohs())
*/ 
uint16_t unpacki16(unsigned char *buf)
{
	unsigned int i2 = ((unsigned int)buf[0]<<8) | buf[1];
	int i;

	// change unsigned numbers to signed
	if (i2 <= 0x7fffu) { i = i2; }
	else { i = -1 - (unsigned int)(0xffffu - i2); }

	return i;
}

/*
** unpacku16() -- unpack a 16-bit unsigned from a char buffer (like ntohs())
*/ 
uint16_t unpacku16(unsigned char *buf)
{
	return ((uint16_t)buf[0]<<8) | buf[1];
}

/*
** pack() -- store data dictated by the format string in the buffer
** 
** c - signed 8-bit 
** C - unsigned 8-bit 
** h - signed 16-bit 
** H - unsigned 16-bit 
** s - string 
** (16-bit length of whole pack is automatically prepended)
*/
uint16_t pack(unsigned char *buf, char *format, ...)
{
    va_list ap;
    int16_t h;
    uint16_t H;
	int8_t c;
	uint8_t C;
    char *s;
    uint16_t  size = 0, len;
    va_start(ap, format);
    for(; *format != '\0'; format++) {
		switch(*format) {
		    case 'c': // 8-bit
				size += 1;
				c = (int8_t)va_arg(ap, int); // promoted
				*buf++ = c;
				break;
			case 'C': // 8-bit unsigned
    			size += 1;
    			C = (uint8_t)va_arg(ap, unsigned int); // promoted
    			*buf++ = C;
    			break;
    		case 'h': // 16-bit
				size += 2;
				h = (int16_t)va_arg(ap, int); // promoted
				packi16(buf, h);
				buf += 2;
				break;
    		case 'H': // 16-bit unsigned
    			size += 2;
    			H = (uint16_t)va_arg(ap, unsigned int);
    			packi16(buf, H);
    			buf += 2;
    			break;
			case 's': // string
				s = va_arg(ap, char*);
				len = strlen(s);
				size += len + 2;
				packi16(buf, len);
				buf += 2;
				memcpy(buf, s, len);
				buf += len;
				break;
			
    		
		}
	}
	va_end(ap);
	return size;
}
/*
** unpack() -- unpack data dictated by the format string into the buffer
*/
void unpack(unsigned char *buf, char *format, ...)
{
	va_list ap;

	int8_t *c;
	uint8_t *C;
	
	int16_t *h;
	uint16_t *H;
	
	char *s;
	uint16_t len, count, maxstrlen=0;
	va_start(ap, format);
	for(; *format != '\0'; format++) {
		switch(*format) {
		    case 'c': // 8-bit
				c = va_arg(ap, int8_t*);
				*c = *buf++;
				break;
			case 'C': //unsigned 8-bit
			    C = va_arg(ap, uint8_t*);
			    *C = *buf++;
			    break;
            case 'h': // 16-bit
				h = va_arg(ap, int16_t*);
				*h = unpacki16(buf);
				buf += 2;
				break;
			case 'H': //unsigned 16-bit
			    H = va_arg(ap, uint16_t*);
			    *H = unpacku16(buf);
			    buf += 2;
			    break;
			case 's': // string
				s = va_arg(ap, char*);
				len = unpacku16(buf);
				buf += 2;
				if (maxstrlen > 0 && len > maxstrlen){ //check overflow  
				    count = maxstrlen - 1; 
				    
				} 
				else count = len;
				memcpy(s, buf, count);
				s[count] = '\0';
				buf += len;
				break;
			default:
				if (isdigit(*format)) { // track max str len
					maxstrlen = maxstrlen * 10 + (*format-'0');
				}
		}
		if (!isdigit(*format)) maxstrlen = 0;
	}
	va_end(ap);
}



void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int main(int argc, char *argv[])
{
//fd_set master; // master file descriptor list
//fd_set read_fds; // temp file descriptor list for select()
int fdmax; // maximum file descriptor number
int listener; // listening socket descriptor
int newfd; // newly accept()ed socket descriptor
int sockfd, numbytes;
fd_set readfds;
//struct sockaddr_storage remoteaddr; // client address
//socklen_t addrlen;

//char buf[256]; // buffer for client data
int nbytes;
char remoteIP[INET6_ADDRSTRLEN];
int yes=1; // for setsockopt() SO_REUSEADDR, below
int i, j, rv;
struct addrinfo hints, *ai, *p;


if (argc != 4) {
        fprintf(stderr,"usage: Client Username server_ip server_port \n");
        exit(1);
    }
    
    
// get us a socket and bind it
memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;


 if ((rv = getaddrinfo(argv[2], argv[3], &hints, &ai)) != 0) 
 {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
 }
 // loop through all the results and connect to the first we can
for(p = ai; p != NULL; p = p->ai_next) {
 if ((sockfd = socket(p->ai_family, p->ai_socktype,
 p->ai_protocol)) == -1) {
 perror("socket");
 continue;
 }
 if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
 perror("connect");
 close(sockfd);
 continue;
 }
 break; // if we get here, we must have connected successfully
}
if (p == NULL) {
 // looped off the end of the list with no connection
 fprintf(stderr, "failed to connect\n");
 exit(2);
}
freeaddrinfo(ai); 
unsigned char buf[1024];
struct sbcp_message join;
join.vrsn=3;
join.type=2;
join.attr_type=2;
strcpy(username,argv[1]);
join.buffer = username;
uint16_t join_data;
join.length = 24;
join.attr_length = 20;

join_data = pack(buf, "ccchhs", join.vrsn, join.type, join.attr_type, join.length, join.attr_length, username) ;
 if (send(sockfd, buf, join_data, 0) == -1){
						perror("send");
						exit(1);
					}
struct sbcp_message send_data;
send_data.vrsn=3;
send_data.type=4;
send_data.attr_type=4;
send_data.length = 512;
send_data.attr_length = 508;
send_data.buffer = send_msg;
//all this inside a loop.
i=0;
j=sockfd;
for(;;)
{
FD_ZERO(&readfds);
FD_SET(sockfd, &readfds);
if(select(sockfd+1, &readfds, NULL,NULL,NULL)==-1)
{
	printf("error");
}
else
{
	//for(int i=0;i<=sockfd;i++)
	//{
		if(FD_ISSET(i, &readfds))
		{
			//if(i==0)
		//	{
				fgets(send_msg,sizeof(send_msg),stdin);
				uint16_t sent_packet = pack(buf, "ccchhs", send_data.vrsn, send_data.type, send_data.attr_type, send_data.length, send_data.attr_length, send_data.buffer);
				if(send(sockfd, buf, sent_packet, 0)== -1)
				{
					perror("send");
				}
		//	}
			
		}
		if(FD_ISSET(j, &readfds))
		{
		if ((numbytes = recv(sockfd, buf, 1023, 0)) <= 0) {
						//perror("recv");
						exit(1);
					}
					buf[numbytes] = '\0';
					printf("%s\n",buf);
				}	  
		}
//	}
}


//sret = select(sockfd+1, &readfds, NULL, NULL, NULL);
//int sret;
//if(sret==0)
//{
	
//}
//else
//{
	//print what you have ie unpack the data and print it. 
//}


return 0;
}