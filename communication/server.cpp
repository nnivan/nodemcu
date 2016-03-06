/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include <iostream>
#include <bitset>
#include <fstream>
#include <cstdio>
#include <memory>
#include <cstring>

#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold

#define MAXDATASIZE 100 // max number of bytes we can get at once

struct Trivium{

    std::string read_file(char file_name[]){

        std::ifstream in(file_name);
        std::string return_value;
        char c;

        if (in.is_open()){
            getline (in, return_value);
            in.close();
            return return_value;
        }
    }

    std::string keystr;
    std::string ivstr;

    Trivium(){
        keystr = read_file("trivium_key.txt");
        ivstr = read_file("trivium_iv.txt");
    }


    void setup(std::bitset<288> &s, std::bitset<3> &t, std::bitset<80> &KEY, std::bitset<80> &INITIAL_VALUE){
        for (int i = 0; i < 288; ++i){
            s[i] = 0;
        }
        t[0] = t[1] = t[2] = 0;
        for(int i=0; i<80; i++)
        {
            s[i] = KEY[i];
        }
        for(int i=0; i<80; i++)
        {
            s[i+93] = INITIAL_VALUE[i];
        }
        s[285] = 1;
        s[286] = 1;
        s[287] = 1;
        for(int j=0; j<4; j++)
        {
            for(int i=0; i<288; i++)
            {
                t[0] = s[65]  ^ s[92];
                t[1] = s[161] ^ s[176];
                t[2] = s[242] ^ s[287];
                t[0] = t[0] ^ (s[90]  & s[91] ) ^ s[170];
                t[1] = t[1] ^ (s[174] & s[175]) ^ s[263];
                t[2] = t[2] ^ (s[285] & s[286]) ^ s[68];
                s <<= 1;
                s[0] = t[2];
                s[93] = t[0];
                s[177] = t[1];
            }
        }

        return;
    }

    std::string encrypt(std::string plaintext){
        std::string ciphertext = plaintext;

        std::bitset<288> s;
        std::bitset<3> t;
        std::bitset<80> key(keystr);
        std::bitset<80> iv(ivstr);


        setup(s, t, key, iv);

        int z = 0;
        int i,x;
        for(int x=0; x<plaintext.size(); ++x)
        {
            for(i=0; i<8; ++i)
            {
                t[0] = s[65]  ^ s[92];
                t[1] = s[161] ^ s[176];
                t[2] = s[242] ^ s[287];
                z |= (t[0] ^ t[1] ^ t[2]) << (i&0b111);

                t[0] = t[0] ^ (s[90]  & s[91] ) ^ s[170];
                t[1] = t[1] ^ (s[174] & s[175]) ^ s[263];
                t[2] = t[2] ^ (s[285] & s[286]) ^ s[68];
                s <<= 1;
                s[0] = t[2];
                s[93] = t[0];
                s[177] = t[1];
            }
            ciphertext[x] ^= char(z);
            z = 0;
        }

        return ciphertext;
    }
};

std::string exec(const char* cmd) {
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) return "ERROR";
    char buffer[128];
    std::string result = "";
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL)
            result += buffer;
    }
    return result;
}

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
    Trivium trivium;
    int sockfd, new_fd, numbytes;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    char msg[MAXDATASIZE];
    int msg_len;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);

        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener
            if ((numbytes = recv(new_fd, msg, MAXDATASIZE-1, 0)) == -1)
                perror("recv");

            msg[numbytes] ='\0';

            printf("server: received '%s'\n", msg);

            strcpy(msg, trivium.encrypt(msg).c_str());

            printf("server: decrypted '%s'\n\n", msg);

            /*char cmd[100] = "echo '";

            strcat(cmd, s);
            strcat(cmd, " - ");
            strcat(cmd, msg);
            strcat(cmd, "' >> information.txt");

            std::cout<<"date >> information.txt\n";
            std::cout<<cmd<<"\n";

            exec("date >> information.txt");
            exec(cmd);*/

            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }

    return 0;
}
