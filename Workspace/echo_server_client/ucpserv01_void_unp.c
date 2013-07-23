//#include "unp.h"
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/un.h>

#define MAXLINE 4096
#define SERV_PORT 162


int main(int argc, char **argv)
{
	int sockfd,n;
	socklen_t len;
	char mesg[MAXLINE];
	struct sockaddr_in servaddr,cliaddr;
	
	if((sockfd=socket(PF_INET,SOCK_DGRAM,0))<0)
	{
		printf("Socket Error");
		exit(0);
	}
	
	memset(&servaddr,0,sizeof(servaddr));

	servaddr.sin_family=PF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
	servaddr.sin_port=htons(SERV_PORT);

	bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

	//dg_echo(sockfd,(sockaddr*)&cliaddr,sizeof(cliaddr));
	
	for(;;)
	{
		len=sizeof(cliaddr);		

		n=recvfrom(sockfd,mesg,MAXLINE,0,(struct sockaddr *)&cliaddr,&len);
		sendto(sockfd,mesg,n,0,(struct sockaddr *)&cliaddr,len);	
	}
	
	return 0;
}






