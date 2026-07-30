// returns squared value of what datagram sends
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdbool.h>

#define DEFAULT_PORT 4321
#define DEFAULT_ADDR INADDR_ANY

#define OUT_BUFFER_SIZE 16

int main(){
    const char* env_port = getenv("SRV_PORT");
    const char* env_lsn_addr = getenv("SRV_LSN_ADDR");

    
    int listenfd;
    
    struct sockaddr_in servaddr;
    struct sockaddr_in cliaddr;
    
    memset(&servaddr, 0, sizeof(servaddr));
    
    // listenfd socket
    listenfd = socket(AF_INET, SOCK_DGRAM, 0); 
    
    servaddr.sin_family = AF_INET; 
    
    if(env_lsn_addr){
        printf("using ");
        int ret = inet_pton(AF_INET, env_lsn_addr, &(servaddr.sin_addr));
        if(ret != 1){
            printf("could not convert address to network form with inet_pton: %s\n", env_lsn_addr);
            exit(1);
        }
        // servaddr.sin_addr.s_addr = inet_addr(env_lsn_addr);
    } else{
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    
    if(env_port) {
        servaddr.sin_port = htons( (unsigned short) atoi(env_port));
    } else {
        servaddr.sin_port = htons(DEFAULT_PORT);
    }
    
    //  bind
    bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr) );
    
    
    
    int sizeof_cliaddr;
    char buffer[1500];

    char out_buffer[OUT_BUFFER_SIZE];

    // server loop
    while(true){

        // blocks untill receives sth
        // https://pubs.opengroup.org/onlinepubs/007904875/functions/recvfrom.html
        sizeof_cliaddr = sizeof(cliaddr);
        int n = recvfrom(listenfd, buffer, sizeof(buffer), 0, (struct sockaddr*) &cliaddr,  &sizeof_cliaddr);


        if(n <= 0){
            printf("Empty packet received\n");
            exit(1);
        }

        if(n > 20){
            // probably more then unsigned long long can handle
            printf("More then 20 bytes received\n");
            exit(1);
        }

        // set end of string
        buffer[n] = '\0';
        int v = atol(buffer);

        int resp = v*v;
        printf("Received %d bytes of value %d. Squard:%d\n", n, v, resp);
        
        int out_length = snprintf(out_buffer, OUT_BUFFER_SIZE , "%d", resp);

        if(out_length <=0 || out_length > OUT_BUFFER_SIZE){
            printf("Output seems wrong");
            exit(1);
        }
        sendto(listenfd, out_buffer, out_length, 0,(struct sockaddr*)  &cliaddr, sizeof_cliaddr);

    }
}
