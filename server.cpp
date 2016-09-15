#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<unistd.h>
#include<fcntl.h>

#include<arpa/inet.h>
#include<netinet/in.h>

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#include<iostream>
#include<string>
#include<map>

using namespace std;

char MAXCLIENTS; //to store max_clients
char *PORT; 
char *IP; //ip and port server is listening on

//get ipv4 or ipv6 addr
void *get_sin_addr(struct sockaddr *sa){
    if(sa->sa_family == AF_INET){//ipv4
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
                                                                                                                              
int main(int argc, char *argv[]){
    
    int yes = 1; //value for setsockopt()-SO_REUSEADDR
    struct addrinfo hints, *servinfo, *p;   //p used for storing addrinfo when iterating
    struct sockaddr_storage clientaddr; //client address
    socklen_t addrlen; //sizeof clientaddr
    char clientIP[INET6_ADDRSTRLEN];
    char buf[256]; //buffer for client data
    
    int gai_status; //return status calling getaddrinfo()
    int listener; //return status calling socket()
    int new_fd; //new accept()ed file descriptor
    
    fd_set master_fds; //set of offical file descriptors
    fd_set read_fds; //set of temp file descriptors for select()
    int fdmax; // maximum file descriptor number
    
    int i,j; //loop index
    
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
            cout << "ERROR! could not bind. listener " << listener << "will be closed" << endl;
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
                    }
                    else{ //send the data to others except listener and owner
                        for(j = 0; j <= fdmax; j++){
                            //send to clients in the master set
                            if(FD_ISSET(j, &master_fds) && j != listener && j != i){
                                cout << "INFO! broadcasting the data from " << i << ">>>" << endl;
                                if(send(j, buf, nbytes, 0) == -1){ // handle send() error
                                    perror("ERROR! send: ");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
               
    
    return 0;
}

