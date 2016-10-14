#include <iostream>
#include<stdio.h>
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
#include <ctype.h>

using namespace std;

//define SBCP header types
#define VRSN 3
#define JOIN 2
#define SEND 4
#define FWD 3
#define NAK 5

//define SBCP attributes
#define USERNAME 2
#define MESSAGE 4
#define REASON 1
#define CLICOUNT 3

//client-self input
#define STDIN 0 

//define the sbcp structure
struct sbcp_message
{
uint16_t vrsn;
uint8_t  type;
uint16_t length;
uint16_t attr_type;
uint16_t attr_length;
char *buffer;
};//structure done

char username[16+1];
char send_msg[512+1];

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
				size += len;
				//packi16(buf, len);
				//buf += 2;
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
				len = unpacku16(buf-2)-4; //get length of string(att_payload)
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

//combine vrsn and type into one uint16_t vn_te
void cob_vrsn_type(unsigned char *buf, uint16_t *vrsn, uint8_t *type)
{
    uint16_t vn_te;
    *type &= 0x7F; //set 0 to the first bit of type
    vn_te = *vrsn << 7 | *type;
    packi16(buf, vn_te);
}

//split vrsn and type from vn_te
void spl_vrsn_type(unsigned char *buf, uint16_t *vrsn, uint8_t *type)
{
    uint16_t vn_te;
    vn_te = unpacku16(buf);
    *vrsn = vn_te >> 7;
    *type = 0x007F & vn_te;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//send all buff data      
int send_all(int fd, unsigned char *buf, int *len){
    int total = 0; //total Bytes sent
    int bytes_left = *len; //Bytes left
    int n_send; //Bytes sent one time;
    
    while(total < *len){
        n_send = send(fd, buf+total, bytes_left, 0);
        if(n_send == -1){ //handle send error
            break;
        }
        total += n_send;
        bytes_left -= n_send;
    }
    *len = total;
    return n_send == -1?-1:0; //-1 on failure, 0 on success
}

int main(int argc, char *argv[])
{
    int sockfd, numbytes; //numbytes-bytes received
    uint16_t length_tmp; //for temp length storage
    int send_B; //number of Bytes sent
    
    //char remoteIP[INET6_ADDRSTRLEN]; // IP
    int rv;
    struct addrinfo hints, *ai, *p;
    
    
    if (argc != 4) {
        fprintf(stderr,"usage: Client Username server_ip server_port \n");
        return 1;
    }
        
        
    // get us a socket and bind it
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;


    if ((rv = getaddrinfo(argv[2], argv[3], &hints, &ai)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 2;
    }
     // loop through all the results and connect to the first we can
    for(p = ai; p != NULL; p = p->ai_next) {
        
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("ERROR! socket: ");
            continue;
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("ERROR! connect: ");
            close(sockfd);
            continue;
        }
        break; // if we get here, we must have connected successfully
    }
    
    if (p == NULL) {
        // looped off the end of the list with no connection
        fprintf(stderr, "failed to connect\n");
        return 3;
    }
    
    freeaddrinfo(ai); 
    
    //prepare the JOIN packet
    unsigned char buf[1024];
    struct sbcp_message join;
    
    join.vrsn = VRSN;
    join.type = JOIN;
    join.attr_type = USERNAME; //USERNAME
    strcpy(username,argv[1]);
    
    length_tmp = strlen(username);
    join.buffer = (char *)malloc(length_tmp * sizeof(char));
    strcpy(join.buffer, username);
    
    length_tmp = 8 + strlen(username);
    join.length = length_tmp;
    
    length_tmp = 4 + strlen(username);
    join.attr_length = length_tmp;
    
    //combine join.vrsn and join.type into one uint16_t vn_te, pack to buf
    cob_vrsn_type(buf, &(join.vrsn), &(join.type));
    
    int join_data; //length of packet
    
    pack(buf+2, (char *)"HHHs", join.length, join.attr_type, join.attr_length, join.buffer);
    buf[join.length] = '\0'; //null-terminated
    join_data = join.length;
    
    //send join packet
    send_B = send_all(sockfd, buf, &join_data);
    if (send_B == -1){
        perror("ERROR! join: ");
        cout << "Only sent " << join_data << " bytes data because of sending error!" << endl; 
    }
    else{
        //cout << "INFO! join: broadcasting " << join_data << " bytes of data to server " << " >>>" << endl;
    }
    
    //free memory
    memset(buf,'\0',sizeof(buf));
    memset(username,'\0',sizeof(username));
    
    fd_set readfds; //dynamic set for select
    fd_set master; // master file descriptor list
    int fdmax; // maximum file descriptor number
    
    FD_ZERO(&readfds);
    FD_ZERO(&master);
    FD_SET(STDIN, &master); 
    FD_SET(sockfd, &master);
    fdmax = sockfd;
    
    cout << "Welcome to chatting room! type '^' to leave. Enjoy!" << endl;
    //all this inside a loop.
    for(;;)
    {
        readfds = master;
        if(select(fdmax+1, &readfds, NULL,NULL,NULL) == -1) //handle select error
        {
        	perror("ERROR! select: ");
            return 4;
        }
        else
        {
        	if(FD_ISSET(STDIN, &readfds))
    		{
    			fgets(send_msg, sizeof(send_msg), stdin);
    			
    			if (send_msg[0] == '^'){
    			    return 6;
    			}
    			
				//prepare the send package
				struct sbcp_message send_data;
                send_data.vrsn = VRSN;
                send_data.type = SEND; //SEND
                send_data.attr_type = MESSAGE; //MESSAGE
                
                length_tmp = strlen(send_msg);
                send_data.buffer = (char *)malloc(length_tmp * sizeof(char));
                strcpy(send_data.buffer, send_msg);
                
                length_tmp = 8 + strlen(send_msg);
                send_data.length = length_tmp;
                
                length_tmp = 4 + strlen(send_msg);
                send_data.attr_length = length_tmp;
                
                //combine send_date.vrsn and send_data.type into one uint16_t vn_te, pack to buf
                cob_vrsn_type(buf, &(send_data.vrsn), &(send_data.type));
                
                int send_data_len; //length of packet
                
                pack(buf+2, (char *)"HHHs", send_data.length, send_data.attr_type, send_data.attr_length, send_data.buffer);
                buf[send_data.length] = '\0';
                send_data_len = send_data.length;
                			
				send_B = send_all(sockfd, buf, &send_data_len);
                if (send_B == -1){
                    perror("ERROR! join: ");
                    cout << "Only sent " << send_data_len << " bytes data because of sending error!" << endl; 
                }
                else{
                    //cout << "INFO! send: broadcasting " << send_data_len << " bytes of data to server " << " >>>" << endl;
                }
    		    memset(buf,'\0',sizeof(buf));
    		    memset(send_msg,'\0',sizeof(send_msg));
    		}
    		
    		if(FD_ISSET(sockfd, &readfds))
    		{
    		    numbytes = recv(sockfd, buf, sizeof(buf), 0);
        		if (numbytes == -1){
        		    perror("ERROR! recv: ");
        		}
                else if(numbytes == 0){
                    cout << "INFO! connection closed by server" << endl;
                    return 5;
                }     
                else{
                    //unpack the package
                    int att_num;
                    struct sbcp_message recv_data;
                    //decode .vrsn .type
                    spl_vrsn_type(buf, &(recv_data.vrsn), &(recv_data.type));
                    //decode .length
                    unpack(buf+2, (char *)"H", &(recv_data.length));
                    switch(recv_data.type){
                        case FWD:
                        {
                            att_num == 2;
                            uint16_t att_urname_len, att_mesg_len;
                            //decode .att_length and contect of USERNAME
                            unpack((buf+6), (char *)"H", &att_urname_len);
                            unpack((buf+8), (char *)"17s", username);
                            //decode .att_length and content of MESSAGE
                            unpack((buf+4+att_urname_len+2), (char *)"H", &att_mesg_len);
                            unpack((buf+4+att_urname_len+4), (char *)"513s", send_msg);
                            if(att_mesg_len != 0){
                                cout << ">>> " << username <<": " << send_msg;
                            }
                            break;
                        }
                        default:
                        {
                            cout << "ERROR! unexpected message type: " << recv_data.type << endl;
                            break;
                        }
                    }
                    //free memory
                    memset(buf,'\0',sizeof(buf));
                    memset(username,'\0',sizeof(username));
                    memset(send_msg,'\0',sizeof(send_msg));
                }
    		}	  
        }
    }
    
    return 0;
}