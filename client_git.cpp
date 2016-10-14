#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<unistd.h>

#include<arpa/inet.h>
#include<netinet/in.h>

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#include<iostream>
#include<string>
#include<map>

#define STDIN 0

#define VERSION 3

#define JOIN 2
#define SEND 4
#define FWD 3

#define ACK 7
#define NAK 5
#define ONLINE 8
#define OFFLINE 6
#define IDLE 9

#define A_USERNAME 2
#define A_MESSAGE 4
#define A_REASON 1
#define A_COUNT 3

using namespace std;

// Thanks BEEJ.US for tutorial on how to use SELECT and pack and unpack functions
// Some parts of the code have been taken from BEEJ.US

unsigned short int getlength(unsigned short int len)
{	//make a 4-bytes-wide payload.
	unsigned short int rem = len%4;
	return len + (4-rem)%4;
}

void packi16 (char *buf, unsigned short int i)
{   //change the host order to network byte order (16bit)
	i = htons(i);
	memcpy(buf,&i,2);
}
void packi32(char *buf, unsigned long i)
{	//change the host order to network byte order (32bit)
	i = htonl(i);
	memcpy(buf,&i,4);
}
unsigned short int unpacki16(char *buf)
{	//change  network byte order to the host order (16bit)
	unsigned short int i;
	memcpy(&i,buf,2);
	i = ntohs(i);
	return i;
}
unsigned long unpacki32(char *buf)
{	//change  network byte order to the host order (32bit)
	unsigned long i;
	memcpy(&i,buf,2);
	i = ntohl(i);
	return i;
}

//Attribute structure, 2 byte type, 2 byte length
struct sbcp_att{
	uint16_t type;
	uint16_t length;
	char *payload;
};

// SBCP message structure,
struct sbcp_msg{
	uint16_t vrsn;								//last 8 bits of version
	uint8_t type;								// the first bit of vrsn and 7 bits type
	uint16_t length;							// 2 bytes length
	unsigned short int num_att;					// this is to record the number of attributes present while decoding
	struct sbcp_att **att_arr;					// a double pointer array to store n attributes
};

char *attribute_to_string(unsigned short int type, char *data){
	//make raw data into an attribute-like string.(store the attribute in a string).
	//Work like an encoder
	unsigned short int len_data;
	if(type == A_COUNT)
		len_data = 3;
	else
		len_data = strlen(data);
	if(data[len_data-1]=='\n')
		data[len_data-1]='\0';
	unsigned short int len = getlength(len_data);
	char *output;
	output = (char *)malloc((len+4)*sizeof(char));
	packi16(output,type);						// encode type
	packi16(output+2,len+4);					// encode length
	memcpy(output+4,data,len_data);				// encode payload
	memset(output+4+len_data,'\0',len-len_data);	// make remainder bits \0
	return output;
}

struct sbcp_att * string_to_attribute(char *packet){
	//extract attribute information from the encoded string came out of the wire
	//work like an decoder
	struct sbcp_att *output;
	output = (struct sbcp_att *)malloc(sizeof(struct sbcp_att));
	output->type = unpacki16(packet);			// decode the type, change the network byte order to host byte order
	output->length = unpacki16(packet+2);		//decode the length from the next 2 bytes of the packet
	output->payload = (char *)malloc(((output->length)-3)*sizeof(char));	// decode the payload
	memcpy(output->payload,packet+4,(output->length));
	output->payload[(output->length)-4] = '\0';
	return output;
}

char *sbcp_to_string(uint16_t vrsn, uint8_t type, unsigned short int num_att, char **att_arr){
	//make encoded attribute strings into a message-string
	//work like an encoder
	unsigned short int total_len=4;
	int i;
	for(i=0; i<num_att; i++){					// get the total length of attributes
		total_len += unpacki16(att_arr[i]+2);
	}
	char *packet = (char *)malloc(total_len*(sizeof(char)));
	uint8_t bit = vrsn & 1;
	uint8_t vrsn_1 = (vrsn>>1);					// setting the VRSN

	type = type | (bit << 7);					// set type and remove the first bit
	packet[0] = vrsn_1;
	packet[1] = type;							// put type and version on the packet
	packi16(packet+2,total_len);				// encode length

	unsigned short int tmp = 4;
	unsigned short int cur_len;
	for(i=0; i<num_att; i++){
		cur_len = unpacki16(att_arr[i]+2);
		memcpy(packet+tmp,att_arr[i],cur_len);	// read every attribute and copy it to packet string
		tmp+=cur_len;
	}
	return packet;
}

struct sbcp_msg * string_to_sbcp(char *packet){
	//extract the message information from a received string
	//work like a decoder
	struct sbcp_msg * output = (struct sbcp_msg *)malloc(sizeof(struct sbcp_msg));

	uint16_t bits = unpacki16(packet);
	output->vrsn = (bits & 0xFF80) >> 7;		// decode version
	output->type = (unsigned char)packet[1];	// decode type
	output->type &= 0x7F;						// making 8th bit of type as 0, as it is a 7 bit field
	output->length = unpacki16(packet+2);		// decode length
	unsigned short int cur_len, tmp = 4, num_att=0;
	while(tmp != output->length){
		cur_len = unpacki16(packet+tmp+2);
		tmp+=cur_len;
		num_att++;								// count the number of attributes
	}

	output->att_arr = (struct sbcp_att **)malloc(num_att*(sizeof(struct sbcp_att *)));	// allocate memory of all attributes
	tmp = 4;
	int i;
	for(i=0; i<num_att; i++){
		cur_len = unpacki16(packet+tmp+2);		// decode each attribute and copy it to our message structure
		output->att_arr[i] = string_to_attribute(packet+tmp);
		tmp+=cur_len;
	}
	output->num_att = num_att;					// set the number of attributes in the structure
	return output;
}

void process(char *packet){
	struct sbcp_msg* sbcp;
	sbcp = string_to_sbcp(packet);				// get the SBCP structure from the received packet string
	unsigned short int type1, type2;
	type1 = unpacki16(packet);					// get the length and type of the packet
	type1&=0x007F;
	int i;
	int num = 1;
	type2 = unpacki16(packet+4);				// get the length and type of the first attribute
	if(type1 == ACK){							// Process message type ACK
		for(i=0; i<sbcp->num_att; i++){
			type2 = sbcp->att_arr[i]->type;
			if(type2 == A_COUNT){
				cout << "Chat Room Count = " << unpacki16(sbcp->att_arr[i]->payload) << endl;	//display count if COUNT attribute received
			}
			else if(type2 == A_USERNAME){
				cout << num++ << ") " << sbcp->att_arr[i]->payload << endl;			// display each username
			}
		}
	}
	else if (type1 == FWD){						// Process message type FWD
		char *uname;
		char *msg;
		for(i=0; i<sbcp->num_att; i++){
			type2 = sbcp->att_arr[i]->type;
			if(type2 == A_MESSAGE){
				msg = sbcp->att_arr[i]->payload;	// get the message string from the payload
			}
			else if(type2 == A_USERNAME){
				uname = sbcp->att_arr[i]->payload;	// get the username of the sender from the attribute
			}
		}
		cout << uname << " : " << msg << endl;
	}
	else if(type1 == OFFLINE){
		cout << sbcp->att_arr[0]->payload << " went OFFLINE" << endl;	// process message type OFFLINE
	}
	else if(type1 == ONLINE){
		cout << sbcp->att_arr[0]->payload << " came ONLINE" << endl;	// process message type ONLINE
	}
	else if(type1 == IDLE){
		cout << sbcp->att_arr[0]->payload << " is now IDLE" << endl;	// process message type IDLE
	}
	else if(type1 == NAK){								// process message type NAK
		cout << sbcp->att_arr[0]->payload << endl;
		//exit(0);
	}
	for(i=0; i<sbcp->num_att; i++){
		free(sbcp->att_arr[i]->payload);			// free memory allocated in the SBCP structure for decoding
		free(sbcp->att_arr[i]);
	}
	free(sbcp);
}

// get_int_addr function taken from BEEJ.US
void *get_in_addr(struct sockaddr *sa)				// get address structure for IPv4 or IPv6 addresses
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[]){
	int error;

	if(argc!=4){									// show error if number of command line arguments are not equal to 4
		fprintf(stderr,"Enter username, server IP, server Port\n");
		return 1;
	}

	char *username = argv[1];

	struct addrinfo hints;
	struct addrinfo *servinfo, *p;
	//char ipstr[INET_ADDRSTRLEN];	//INET6_ADDRSTRLEN for IPv6

	//Getting my address
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if( (error = getaddrinfo(argv[2], argv[3], &hints, &servinfo)) != 0){	// get address info of server for given IP address and PORT number
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(error));
		exit(1);
	}

	int sockfd;
	for(p=servinfo; p!=NULL; p=p->ai_next){
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol))== -1){	// create client socket
			perror("client: socket");
			continue;
		}
		break;
	}
	if(p==NULL){
		fprintf(stderr, "my sock fd: failed to connect\n");
		return 2;
	}

	int size = 1024;
	char *buf = (char *)malloc((size+1)*sizeof(char));

	unsigned short int len;
	int num_bytes;
	if( (error = connect(sockfd,p->ai_addr,p->ai_addrlen)) == -1){			// connect to server IP Address and PORT number
		perror("client: connect");
	}

	freeaddrinfo(servinfo);

	fd_set master;    // master file descriptor list
	fd_set read_fds;  // temp file descriptor list for select()
	int fdmax;        // maximum file descriptor number
	FD_ZERO(&master);    // clear the master and temp sets
	FD_ZERO(&read_fds);

	FD_SET(STDIN,&master);
	FD_SET(sockfd,&master);
	fdmax = sockfd;

	char **att_arr;
	att_arr = (char **)malloc(1*sizeof(char*));
	char *packet;
	int i;

	struct timeval t;
	t.tv_sec = 1000;		// Set idle timeout to 10 seconds
	t.tv_usec = 0;
	int idle = 0;

	att_arr[0] = attribute_to_string(A_USERNAME,username);		// Send JOIN request to server
	packet = sbcp_to_string(VERSION,JOIN,1,att_arr);
	len = unpacki16(packet+2);
	if( (error = send(sockfd,packet,len,0)) == -1){
		perror("client: JOIN");
	}
	
	int flag;
	while(1){
		flag = 0;
		read_fds = master;
		if( select(fdmax+1, &read_fds, NULL, NULL, &t) == -1){		// Select between client socket and STDIN file descriptors
			perror("client: select");
			exit(4);
		}
		if(!(FD_ISSET(STDIN,&read_fds)) && t.tv_sec==0 && idle==0){		// If client timeout occurs send IDLE message to server and reset the counter to 10
			idle = 1;
			packet = sbcp_to_string(VERSION,IDLE,0,NULL);
			if( (error = send(sockfd,packet,4,0)) == -1){
				perror("client: send");
			}
			t.tv_sec = 10;
			printf("You are idle\n");
		}
		for(i=0; i<=fdmax; i++){
			if(FD_ISSET(i,&read_fds)){
				if(i==sockfd){
					flag = 1;
					memset(buf,'\0',size);
					num_bytes = recv(sockfd,buf,1000,0);			// receive message from server
					if(num_bytes == -1){
						perror("client: recv");
					}
					else if(num_bytes == 0){
						printf("Connection closed by server\n");
						exit(0);									// if number of bytes received is zero, it means server has closed the connection
					}
					else{
						process(buf);								// process function to decode and taken actions on the received packet
					}
				}
				if(i==STDIN){										// If user has entered something go inside and reset the IDLE counter to 10
					t.tv_sec = 10;
					idle = 0;
					getline(&buf,(size_t *)&size,stdin);			// Get the user input
					len = strlen(buf);
					att_arr[0] = attribute_to_string(A_MESSAGE,buf);		// pack the Message
					packet = sbcp_to_string(VERSION,SEND,1,att_arr);		// get the final packet to be sent
					len = unpacki16(packet+2);
					if( (error = send(sockfd,packet,len,0)) == -1){			// send the message to the server
						perror("client: send");
					}
					free(att_arr[0]);								// free the dynamically allocated memory
					free(packet);
				}
			}
		}
		if (flag == 0)
			t.tv_sec = 10;												// Reset the IDLE counter to 10
	}
	return 0;
}