#include<iostream> //c++ libraries
#include<string>
#include <cstdlib>
#include <cstring>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>		// defines perror(), herror() 
#include <fcntl.h>		// set socket to non-blocking with fcntrl()
#include <unistd.h>
#include <string.h>
#include <assert.h>		//add diagnostics to a program
#include <stdarg.h>     //variable arguments
#include <map> //for map container

#include <netinet/in.h>		//defines in_addr and sockaddr_in structures
#include <arpa/inet.h>		//external definitions for inet functions
#include <netdb.h>		//getaddrinfo() & gethostbyname()

#include <sys/socket.h>		//
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/select.h>		// for select() system call only
#include <sys/time.h>		// time() & clock_gettime()

using namespace std;

//SBCP attributes
typedef struct sbcp_att{
    uint16_t type;
    uint16_t length;
    char *payload;
}att;

//SBCP message struct
typedef struct sbcp_msg{
    uint16_t vrsn;   //vrsn 9-bit
    uint8_t type;   //type 7-bit
    uint16_t length; //2-bytes length of sbcp message
    //uint8_t att_num; //number of sbcp attrs
    att **att_array; //pointer array to store attributes
}msg;

//user profile
typedef struct user_info{
    string user_name;
    int8_t status; //1-online, -1-offline, 0-idle
}user;

map<int, user>usrs_map;
map<int, user>::iterator it;

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

char MAXCLIENTS; //to store max_clients
char *PORT; 
char *IP; //ip and port server is listening on

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

int dup_name_check(char * ur_name)
{
    int flag = 0;
    string urname(ur_name);

    for(it = usrs_map.begin(); it != usrs_map.end(); it++){
        if(urname.compare(it->second.user_name) == 0){
            flag = 1;
            break;
        }
    }
    return flag;
}

//decode msg.vrsn .type .length
msg * buf2msg(unsigned char *buf)
{
    msg * one_msg = (msg *)malloc(sizeof(msg));
    
    //unpack msg.vrsn .type .length
    spl_vrsn_type(buf, &(one_msg->vrsn), &(one_msg->type));
    unpack(buf+2, (char *)"H", &(one_msg->length));
    
    return one_msg;
}

//decode att.type .length
att * buf2att(unsigned char *buf)
{
    att * one_att = (att *)malloc(sizeof(att));
    unpack(buf, (char *)"HH", &(one_att->type), &(one_att->length));
    
    return one_att;
}

//pack struct to buf(encoder)
void msg2buf(unsigned char *buf, uint16_t vrsn, uint8_t type, uint16_t length)
{
    //uint16_t pack_size;
    cob_vrsn_type(buf, &vrsn, &type);
    ////cout << "length: " << length << endl;
    pack(buf+2, (char *)"H", length);
}

void att2buf(unsigned char *buf, att * one_att)
{
    //uint16_t pack_size;
    pack(buf, (char *)"HHs", one_att->type, one_att->length, one_att->payload);
}
 
 
//server process logic
/*unsigned char * ser_logic(unsigned char *buf)
{
    
}*/


//get ipv4 or ipv6 addr
void *get_sin_addr(struct sockaddr *sa){
    if(sa->sa_family == AF_INET){//ipv4
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
                                                                                                                              
int main(int argc, char *argv[]){
    
    int yes = 1; //value for setsockopt()-SO_REUSEADDR
    struct addrinfo hints, *servinfo, *p;   //p used for storing addrinfo when iterating
    struct sockaddr_storage clientaddr; //client address
    socklen_t addrlen; //sizeof clientaddr
    char clientIP[INET6_ADDRSTRLEN];
    unsigned char buf[1024]; //buffer for client data
    
    int gai_status; //return status calling getaddrinfo()
    int listener; //return status calling socket()
    int new_fd; //new accept()ed file descriptor
    uint16_t client_num = 0; //number of online client in the chat room
    
    fd_set master_fds; //set of offical file descriptors
    fd_set read_fds; //set of temp file descriptors for select()
    int fdmax; // maximum file descriptor number
    FD_ZERO(&master_fds);
    FD_ZERO(&read_fds);
    
    short int i,j; //loop index
    
    //
    
    //input arg number check
    if(argc != 4){
        //fprintf(stderr, "command format: server server_ip server_port max_cilents\n");
        cerr << "ERROR! command format: server server_ip server_port max_cilents" << endl;
        return 1;
    }
    
    //store ip, port and max_clients
    IP = argv[1];
    PORT = argv[2];
    MAXCLIENTS = atoi(argv[3]);
    
    //set hints 
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    //gai_status = getaddrinfo(IP, PORT, &hints, &servinfo);
    //cout << servinfo->ai_family <<" " << servinfo->ai_socktype << " " <<servinfo->ai_protocol <<endl;
    
    //////////////prepare servinfo & handle error of getaddrinfo///////////////////////////
    if((gai_status = getaddrinfo(IP, PORT, &hints, &servinfo)) != 0){
        cerr << "ERROR! getaddrinfo: " << gai_strerror(gai_status) <<endl;
        return 2;
    }
    
    //////////////////////initial a socket and bind it to the port////////////////////////////
    for(p = servinfo; p != NULL; p = p->ai_next){
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        cout << "INFO! create listener socket: "<< listener << endl;
        //return -1, error
        if(listener < 0){
            continue;
        }
        
        //port reuse
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if(bind(listener, p->ai_addr, p->ai_addrlen) < 0){
            cout << "ERROR! could not bind. listener " << listener << " will be closed" << endl;
            close(listener);
            continue;
        }
        break; // bind to the first successful one
    }
    
    //socket create/bind error
    if(p == NULL){
        cerr << "ERROR! socket: failed to create or bind" << endl;
        return 3;
    }
    
    freeaddrinfo(servinfo);
    
    ////////////////////////////Listen///////////////////////////////////////////
    //handle listening error
    int listen_res; 
    listen_res = listen(listener, MAXCLIENTS);
    cout << "INFO! Start Listening on port " << PORT << " >>>" << endl;
    if(listen_res == -1){
        perror("ERROR! listen:");
        return 4;
    }
    
    //add listener to master set
    FD_SET(listener, &master_fds);
    //store current maximum fd number
    fdmax = listener;
    
    ///////////////////////////////////main loop///////////////////////////////////
    while(1){
        //non-block listening and reading
        read_fds = master_fds;
        uint16_t length_tmp;
        int sel_res;
        sel_res = select(fdmax+1, &read_fds, NULL, NULL, NULL);
        //handle select error
        if(sel_res == -1){
            perror("ERROR! select: ");
            return 5;
        }
        
        //loop through current connections, looking for data to read.
        for(i=0; i<=fdmax; i++){
            if(FD_ISSET(i, &read_fds)){ //find one in the set
                if(i == listener){//listner has got a new fd
                    //accept the new connection
                    addrlen = sizeof clientaddr;
                    new_fd = accept(listener, (struct sockaddr *)&clientaddr, &addrlen);
                    
                    if(new_fd == -1){//handle accept() error
                        perror("ERROR! accept: ");
                    }
                    else{
                        FD_SET(new_fd, &master_fds); //add new fd to master set
                        if(new_fd > fdmax){ //track max fd
                            fdmax = new_fd;
                        }
                        
                        //print connection info
                        cout << "SUCCESS! new connection from " << inet_ntop(clientaddr.ss_family, get_sin_addr((struct sockaddr*)&clientaddr), clientIP, INET6_ADDRSTRLEN) << " on socket " << new_fd << endl;
                    }
                }
                else{ //handle data from one ready client
                    int nbytes;
                    nbytes = recv(i, buf, sizeof buf, 0);
                    if(nbytes <= 0){
                        if(nbytes < 0){ //handle recv() error
                            perror("ERROR! receive: ");
                        }
                        else if(nbytes == 0){ // client hung up
                            cout << "INFO! socket " << i << " hung up" << endl;
                        }
                        close(i); //clear socket
                        FD_CLR(i, &master_fds);
                        usrs_map.erase(i); //free user name
                        if (client_num > 0){
                            client_num--; //a client leaves the chat room    
                        }
                        cout << "INFO! now number of client: " << client_num << endl;
                    }
                    else{ 
                        //unpack the buf to msg and att structs
                        unsigned char send_buf[1024];
                        int dup_flag = 0; //0-no dup, 1-has dup
                        uint8_t att_num;
                        msg * rev_msg = new msg();
                        rev_msg = buf2msg(buf); //decode msg.vrsn .type .length
                        cout << "INFO! receive " << rev_msg->length << " bytes of data from socket " << i << endl;
                        //decode att by msg.att_num
                        switch(rev_msg->type){
                            case 2: //JOIN
                            {
                                att_num = 1;
                                //rev_msg->att_num = att_num;
                                rev_msg->att_array = (att **)malloc(att_num * sizeof(att *));
                                att *att_urname = (att *)malloc(sizeof(att));
                                att_urname = buf2att(buf+4); //decode att.type .length
                                rev_msg->att_array[0] = att_urname; //connect msg and att
                                att_urname->payload = (char *)malloc((att_urname->length-4) * sizeof(char));
                                unpack(buf+8, (char *)"17s", att_urname->payload);
                                
                                //check duplication of username
                                dup_flag = dup_name_check(att_urname->payload);
                                if(dup_flag == 1){ //remove this client
                                    cout << "INFO! username duplication occured" << endl;
                                    close(i); //clear socket
                                    FD_CLR(i, &master_fds); 
                                    free(rev_msg); free(att_urname);
                                    
                                    //get NAK packet
                                }
                                else{ //add to user map
                                    user * new_user = new user();
                                    string name_tmp(att_urname->payload);
                                    new_user->user_name = name_tmp;
                                    new_user->status = 1;
                                    usrs_map[i] = *new_user; //add new user to map
                                    client_num++; //a new client join the chat room
                                    cout << "INFO! client *" << new_user->user_name << "* join the chat room" << endl;
                                    cout << "INFO! now number of client: " << client_num << endl;
                                    free(new_user); free(att_urname); free(rev_msg);
                                    //get ACK packet
                                }
                                break;
                            }
                                
                            case 4: //SEND
                            {
                                //decode buf to att.msg
                                att_num = 1;
                                //rev_msg->att_num = att_num;
                                ////rev_msg->att_array = (att **)malloc(att_num * sizeof(att *));
                                //2.make att_msg struct
                                att * att_msg = (att *)malloc(sizeof(att));
                                att_msg = buf2att(buf+4); //decode att.type .length
                                ////rev_msg->att_array[0] = att_msg; //connect msg and att
                                att_msg->payload = (char *)malloc((att_msg->length-4) * sizeof(char));
                                unpack(buf+8, (char *)"513s", att_msg->payload);
                                
                                //get FWD packet
                                cout << "INFO! start encoding FWD packet >>>" << endl;
                                att_num = 2; //att_msg and att_urname
                                //1.make att_urname struct
                                att *att_urname = (att *)malloc(sizeof(att));
                                att_urname->type = (uint16_t)USERNAME;  //.type-USERNAME
                                ////cout << ">>> step 1" << endl; 
                                it = usrs_map.find(i);
                                char *ur_name = new char [it->second.user_name.length()+1];
                                strcpy(ur_name, it->second.user_name.c_str());
                                ////cout << ">>> step 2" << endl;
                                att_urname->payload = (char *)malloc(strlen(ur_name) * sizeof(char));
                                strcpy(att_urname->payload, ur_name); 
                                ////cout << ">>> step 3: length of send_buf is " << strlen((const char*)send_buf) << " bytes"<< endl;
                                att_urname->length = 4 + strlen(ur_name); //.length
                                
                                length_tmp = 4 + att_msg->length + att_urname->length;
                                msg2buf(send_buf, (uint16_t)VRSN, (uint8_t)FWD, length_tmp);
                                //cout << ">>> step 4: length of send_buf is " << strlen((const char*)send_buf) << " bytes"<< endl;
                                att2buf(send_buf+4, att_urname);
                                //cout << ">>> step 5: length of send_buf is " << strlen((const char*)send_buf) << " bytes"<< endl;
                                att2buf(send_buf+4+att_urname->length, att_msg);
                                //cout << ">>> step 6: length of send_buf is " << strlen((const char*)send_buf) << " bytes"<< endl;
                                send_buf[length_tmp] = '\0';
                                //cout << ">>> step 7: length of send_buf is " << strlen((const char*)send_buf) << " bytes"<< endl;
                                cout << "INFO! finish making a FWD packet of " << length_tmp << " bytes" << endl;
                                break;
                            }
                                
                            default:
                            {
                                cout << "ERROR! unexpected message type: " << rev_msg->type << endl;
                                break;
                            }
                        }
                        
                        //send the new packet to others except listener and owner
                        if(!(strlen((const char*)send_buf) == 0)){
                            for(j = 0; j <= fdmax; j++){
                            //send to clients in the master set
                                if(FD_ISSET(j, &master_fds) && j != listener && j != i){
                                    
                                    int send_B = 0; //Bytes have been sent
                                    int buf_len = 0; //length of buff
                                    
                                    buf_len = length_tmp;
                                    send_B = send_all(j, send_buf, &buf_len);
                                    
                                    if(send_B == -1){ // handle send() error
                                        perror("ERROR! sendall: ");
                                        cout << "Only sent " << buf_len << " bytes data because of sending error!" << endl; 
                                    }
                                    else{
                                        cout << "INFO! broadcasting " << buf_len << " bytes of data from socket " << i << " to socket " << j << " >>>" << endl;
                                    }
                                }
                            }
                        }
                        
                        //clear buf[]
                        memset(buf, '\0', sizeof buf);
                        memset(send_buf, '\0', sizeof send_buf);
                    }
                }
            }
        }
    }
               
    
    return 0;
}

