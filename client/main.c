#include <stdio.h>
#include <strings.h> 

#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <stdlib.h>
#include <stdbool.h> 

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
		destaddr.sin_addr.s_addr = htons(env_addr);
	}else{
		destaddr.sin_port = htons(DEFAULT_ADDR);
	}

	if(env_port){
		destaddr.sin_addr.s_addr = htonl(env_port);	
	}else{
		destaddr.sin_port = htonl(DEFAULT_PORT);
	}
 	
	int number = htonl(4); 


	int len = sendto(sockfd, &number, sizeof(int), 0, &destaddr, sizeof(destaddr)); 
	if(len == -1){
		perror("Failed to send a message"); 
	}

	close(sockfd);
}
