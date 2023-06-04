#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>

int print_data_of_socket(unsigned char *memory, size_t size){
    char current_char;
    for (int i = 0; i < (int)size; i++){
        current_char = memory[i];
        if (current_char != 0x0){
            printf("%c", current_char);
        }
        else{
            return 0;
        }
    }
    return 1;
}


int main(){

    int sock, sock_size, buffer_size;
    size_t data_size;
    struct sockaddr saddr;
    unsigned char *p_memory;
    int real_packet;

    buffer_size = 65536;
    p_memory = (unsigned char *)malloc(buffer_size);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!sock){
        printf("Couldn't open a socket!\n");
        return -1;
    }
    else {
        sock_size = sizeof(saddr);
        printf("Created a socket successfuly!\n");
        while(1){
            data_size = recvfrom(sock, p_memory, buffer_size, 0, &saddr, &sock_size);
            if (data_size > 0){
                real_packet = print_data_of_socket(p_memory, data_size);
                if(real_packet){
                    printf("\n");
                }
            }
        }
    }
    return 0;

}