#include <stdio.h>
#include <strings.h> 

#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <stdlib.h>
#include <stdbool.h> 
#include <string.h>

#define DEFAULT_PORT 4321 
#define DEFAULT_ADDR INADDR_ANY 


int main(){
	const char* env_port = getenv("SERVER_PORT"); 
	const char* env_addr = getenv("SERVER_ADDRESS");
 
	struct sockaddr_in destaddr = {0};  
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0); 

	if(sockfd == -1){
		exit(EXIT_FAILURE);
	}

	destaddr.sin_family = AF_INET; 
	
	if(env_addr){
		inet_pton(AF_INET, env_addr, &destaddr.sin_addr);
	}else{
		inet_pton(AF_INET, "127.0.0.1", &destaddr.sin_addr);
	}

	if(env_port){
		destaddr.sin_port = htons(atoi(env_port));	
	}else{
		destaddr.sin_port = htons(DEFAULT_PORT);
	}
 	
	for (int i=1; i<=10; i++){
		char msg[20];
		snprintf(msg, sizeof(msg), "%d", i);
		sleep(2);
		int len = sendto(sockfd, &msg, strlen(msg), 0, (struct sockaddr *)&destaddr, sizeof(destaddr));

    if(len == -1){
      perror("Failed to send a message"); 
    }
  }

	close(sockfd);
}
