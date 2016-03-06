
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <string>
#include <iostream>
#include <bitset>
#include <fstream>
#include <cstdio>
#include <memory>
#include <cstring>

#include <arpa/inet.h>

#define PORT "3490" // the port client will be connecting to

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
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{

    std::string status = exec("cat /media/card/status.txt");
    exec("echo \'f\' > /media/card/status.txt");

    Trivium trivium;
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if (argc != 3) {
        fprintf(stderr,"usage: client hostname\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    int buf_len;

    //fgets(buf, sizeof(buf), stdin);
    buf_len = strlen(argv[2]);
    argv[2][buf_len] = '\0';
    strcpy(argv[2], trivium.encrypt(argv[2]).c_str());

    if (!fork()) {
        if (send(sockfd, argv[2], buf_len, 0) == -1) {
            perror("send");
            exit(1);
        }
        printf("client: send '%s'\n",argv[2]);
    }

    close(sockfd);

    if(status[0] == 's'){
        exec("echo \'s\' > /media/card/status.txt");
    }
    if(status[0] == 'c'){
        exec("echo \'c\' > /media/card/status.txt");
    }

    return 0;
}
