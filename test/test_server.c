#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/wait.h>
#include <dlfcn.h>
void server_test() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(8888);
    int ret = bind(server_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    printf("[server_test]bind ret %d\n",ret);
    ret = listen(server_fd, 10);
    

    int connfd = accept(server_fd, (struct sockaddr *) NULL, NULL);

    

    char msg_recv[2];
    
    while(1){
       int read_ret = read(connfd, msg_recv, sizeof(msg_recv));
    }
    
    close(connfd);

}

void client_test() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8888);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if (ret < 0) {
        printf("[client_test]error in connnect peers");
        return;
    } else {
        printf("[client_test]connect to peers");
    }
    char msg_send[2] = {'a', 'b'};
    while(1){
        int write_ret = write(sockfd, msg_send, 2);
        usleep(300000);
        printf("[client_test]write_ret:%d\n", write_ret);
    }
    

}

int main() {
    server_test();
    return 0;
}