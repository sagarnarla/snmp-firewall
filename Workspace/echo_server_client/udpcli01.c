//#include "unp.h"

#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/un.h>

#define MAXLINE 4096
#define SERV_PORT 162


int main(int argc,char **argv)
{
	int sockfd,n,len;
	struct sockaddr_in servaddr;
	char sendline[MAXLINE],recvline[MAXLINE];

	
	//if(argc!=2)
	//	fputs("Usage: udpcli <IP Address>",stdout);
	
	memset(&servaddr,0,sizeof(servaddr));
	servaddr.sin_family=PF_INET;
	servaddr.sin_port=htons(SERV_PORT);
	servaddr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
	//inet_pton(PF_INET,argv[1],&servaddr.sin_addr);

	sockfd=socket(PF_INET,SOCK_DGRAM,0);

	//dg_cli(stdin,sockfd,(SA*)&servaddr,sizeof(servaddr));

	while(fgets(sendline,MAXLINE,stdin)!= NULL)
	{
		len=sizeof(servaddr);		
		sendto(sockfd,sendline,strlen(sendline),0,(struct sockaddr *)&servaddr,len);
		n=recvfrom(sockfd,recvline,MAXLINE,0,(struct sockaddr *)&servaddr,&len);
		recvline[n]=0;
		fputs(recvline,stdout);
	}

	return 0;
}
