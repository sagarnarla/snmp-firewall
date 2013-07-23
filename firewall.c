/*
 *	APP-PROXY : An Application Layer Proxy Firewall for SNMP v1 Protocol in a PAT Network
 */
 
/*
 *	Requirement  :   /etc/appconfig.conf (EXAMPLE @ END OF FILE)
 *	Permission for : /var/log/applog.log
 *
*/

#include<sys/socket.h>
#include<netinet/in.h>
#include<stdlib.h>
#include<sys/un.h>
#include<sys/time.h>
#include<stdio.h>
#include<pthread.h>
#include<semaphore.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <error.h>
#include <errno.h>


// GLOBAL DEFINITIONS

#define MAXLINE 4096 // Maximum message size
#define MAXPORTSUPPORT 256 // Maximum allowed listening ports
#define BARR_LENGTH 6 // Maximum number of message types that can be barred (only 6 types)
#define SNMPTRAP 162 // TRAP message port
#define SNMPNONTRAP 161 // NON-TRAP message port

// STRUCTURES

struct msg_buffer // Message read buffer queue
{
	u_char pkt[MAXLINE];
	int length;
	int sock;
	struct msg_buffer *next;
	struct msg_buffer *prev;
};

struct reqid_list // Request Id list
{
	long reqid;
	long myreqid;
	struct reqid_list *next;
};

struct hash_ip // Port to IP Address hash map array
{
	struct in_addr ip;
	//int16_t port;
	int sock;
	struct hash_ip *next;
};

typedef struct hash_ip hash_map;
typedef struct reqid_list id_q;
typedef struct msg_buffer rd_q;

// FUNCTIONS PROTOTYPES

void *rd_service(); // Message Service thread
int push_rd_q(int); // Message Read and Buffer function 
void end(int);
netsnmp_pdu* parse(u_char*,size_t ); // Calls Parse function from net-snmp package
int assess(netsnmp_pdu*,int); // Function calling all Firewall Rules
int barred(netsnmp_pdu*); // Function checking for barred message types
int config_init(void); // Function reading config file : /etc/appconfig.conf
int binder(int,char*,int16_t); // Port to IP Address binder
int externmapper(int,struct in_addr); // Port to External Network IP Address binder
int internmapper(int,struct in_addr); // Port to Internal Network IP Address binder
int forward(char*,int,struct in_addr,int); // Function forwarding a valid packet
long genmyreqid(); // Function re-allocating a new Request Id

// GLOBAL VARIABLES

//struct sockaddr_in servaddr[2];
int *sockfd,sock_no;
int barr[BARR_LENGTH];
FILE *log;
char log_str[50];
//char *community;
pthread_t rd_thread;
//sem_t rd_mutex;
pthread_mutex_t rd_mutex;
rd_q *rd_front,*rd_rear;
id_q *id_head;
hash_map *internmap,*externmap;



// C CODE

void initialize() // Function initializing variables and reading configuration file
{
	int i,er;
	//Binding and Address allocation
	
	printf("Initializing");
		
	//OPEN LOGFILE
	log=fopen("/var/log/applog.log","w");
	if(log == NULL)
	{
		printf("Log file cannot be opened");
		end(-1);
	}
	fputs("Logging Enabled \n",log);
	
	//ENABLING SIGNAL HANDLER
	signal(SIGINT,end); // Trap signal SIGINT (CTRL-C) to facilitate a gracefull termination 
		
	//INITIALIZE VARIABLES
	
	rd_rear = NULL; // Doubled headed Queue Head
	rd_front = NULL; // Doubled headed Queue Tail
	id_head = NULL; 
	sock_no = 0;
		
	//READING CONFIG FILE
	if(config_init())
	{	
		fputs("Configuration File Error",log);
		end(-1);
	}
	
	// SPAWN NEW READ THREAD
	
	pthread_create(&rd_thread,NULL,rd_service,NULL);
	
	// INITIALIZE PTHREAD MUTEX
		
	pthread_mutex_init(&rd_mutex,NULL);
	//rd_mutex = PTHREAD_MUTEX_INITIALIZER;
	
	fflush(log);
	
}



void *rd_service()
{
	rd_q *delnode;
	u_char msg[MAXLINE];
	int ctr,len;
	//int16_t port;
	int sock;
	netsnmp_pdu *status;
	
	printf("Read Service thread running");
		
	while(1)
	{
		//sem_wait(&rd_mutex); //CRITICAL SECTION BEGINS
		pthread_mutex_lock(&rd_mutex);
		
		if(rd_front == NULL && rd_rear == NULL) // Empty Queue -- Nothing to do
		{
			pthread_mutex_unlock(&rd_mutex);
			//sem_post(&rd_mutex); //CRITICAL SECTION ENDS
			continue;
		}
		else // Pending messages -- Pop queue and read
		{
			memset(msg,0,MAXLINE);
			
			delnode=rd_front;
			for(ctr=0;ctr<delnode->length;ctr++) // Copy message from queue
				msg[ctr]=delnode->pkt[ctr];			
			len = delnode->length;
			//port = delnode->port;
			sock = delnode->sock;
			if(rd_front == rd_rear)
			{
				rd_front = NULL;	
				rd_rear = NULL;
				
			}
			else
			{
				rd_front = delnode->next;
				//free(delnode);
			}
			free(delnode);
			delnode = NULL;
			pthread_mutex_unlock(&rd_mutex);
			//sem_post(&rd_mutex); //CRITICAL SECTION ENDS
		}
		
		status=parse(msg,len); // Parsing raw message
		if(status) // Status to check Packet Intregity
		{
			fputs("\nIntegrity Check Passed : ",log);
			if(!barred(status)) // Check for barred message
				if(assess(status,sock)) // Apply other firewall rules
					fputs(" Droping packet\n",log);
			free(status);
		}
		else
		{
			fputs("\nIntegrity Check Failed : Droping packet\n",log);
		}		
		fflush(log);	
	
	}
	
	
}


int push_rd_q(int sockfd) // Push a pending message into read buffer -- Done whenever select returns
{
	rd_q *q_node;
	//char msg[MAXLINE];
	
	int len;
		
	q_node=(rd_q *)malloc(sizeof(rd_q));
	if(q_node == NULL)
	{
		fputs("Malloc failed (push_rd_q)",log);
		return -1;
	}
	
	
	
		
	len=recv(sockfd,q_node->pkt,MAXLINE,0);
	q_node->length=len+1;
	q_node->sock=sockfd;
		
	q_node->next = NULL;
	q_node->prev = NULL;
				
	//ADDING NODE TO RD_Q LINKLIST
		
	//sem_wait(&rd_mutex); //CRITICAL SECTION BEGINS
	pthread_mutex_lock(&rd_mutex);
	
	if(rd_front == NULL && rd_rear ==NULL)
	{
		//rd_front = q_node;
		//rd_rear = q_node;
		rd_front = q_node;
		rd_rear = q_node;
	}
	else
	{
		//rd_rear->next=q_node;
		//rd_rear=q_node;
		q_node->prev = rd_rear;
		rd_rear->next = q_node;
		rd_rear = q_node;
	}
		
	pthread_mutex_unlock(&rd_mutex);
	//sem_post(&rd_mutex); //CRITICAL SECTION ENDS
	
	return 0;
}

int main()
{
	int i=0,rd_sock;
	struct timeval timeout;
	fd_set socks;
		
	initialize(); 
	
	printf("\nmain ");
	
	for(;;) // Infinite Read loop 
	{
		FD_ZERO(&socks);
	
		//FD_SET(sockfd[0],&socks);
		for(i=0;i<sock_no-1;i++)
			FD_SET(sockfd[i],&socks);
	
			
		
		timeout.tv_sec=1;
		timeout.tv_usec=0;		
		
		rd_sock=select(sockfd[sock_no-1]+1,&socks,(fd_set *)0,(fd_set *)0,NULL); // Select returns whenver any port has a pending packet	
		//printf("Select returned");

		if(rd_sock<0)
		{
			fputs("Select Error",log);
			end(-1);
		}
		if(rd_sock==0)
			fputs(".",log);
		else
		{
			for(i=0;i<sock_no-1;i++)
			{
				if(FD_ISSET(sockfd[i],&socks))
				{	
					
					if(push_rd_q(sockfd[i]))
						fputs("Cannot be serviced\n",log);
					
				}
				else
					fputs(".",log);
			}
		}

		fflush(log);
	}
	
	return 0;
}		

void end(int value)
{
	//sem_destroy(&rd_mutex);
	pthread_mutex_destroy(&rd_mutex);
	fclose(log);
	//free(sockfd);
	exit(value);
}

/////////////////////////////


//size_t newpktlen=0,offset=0;
//u_char *newpkt;
//size_t pktlen=46;

netsnmp_pdu* parse(u_char *pkt,size_t pktlen) // Calls Parse function from net-snmp package
{

	size_t newpktlen=0,offset=0;
	u_char *newpkt;	
	netsnmp_session session; // dummy variable needed for the parse function
	netsnmp_pdu *pdu; // Holds the parsed packet
	netsnmp_variable_list *vars; // Holds the Varible bindings
	int status=45,ctr,i;
   
	newpktlen=0;
	offset=0;
	
	pdu = (netsnmp_pdu *) malloc(sizeof(netsnmp_pdu));
    	if (pdu) // Alloting certain necessary data values to pdu
	{
        	//pdu->version = SNMP_VERSION_1;
        	//pdu->command = SNMP_MSG_RESPONSE;
       		//pdu->errstat = SNMP_DEFAULT_ERRSTAT;
        	//pdu->errindex = SNMP_DEFAULT_ERRINDEX;
        	pdu->securityModel = SNMP_DEFAULT_SECMODEL;
        	pdu->transport_data = NULL;
        	pdu->transport_data_length = 0;
        	pdu->securityNameLen = 0;
        	pdu->contextNameLen = 0;
        	pdu->time = 0;
        	pdu->reqid = snmp_get_next_reqid();
        	pdu->msgid = snmp_get_next_msgid();
    	}	
	else
	{
		sprintf(log_str,"Malloc Failed (parse)");
		fputs(log_str,log);
		return NULL;
	}
	//pkt=msg;
	//pkt_len=msg_len;
	
	printf("Message before parsing\n");
	for(ctr=0;ctr<(int)pktlen;ctr++)
		printf("%x",pkt[ctr]);
	printf("\n\n");	
	
	status=snmp_parse(&session,pdu,pkt,pktlen); // Actual call to the net-snmp parse function
	if(status != 0)
		return (NULL);
	
	printf("\n\n");	
	printf("Status %d",status);

	
	for(vars = pdu->variables; vars; vars = vars->next_variable)
        {
		print_variable(vars->name, vars->name_length, vars);
		
	}
	return (pdu);
	
	//--THIS PART DOES NOT EXECUTE--
	//-- THIS PART RECOMPILES THE PDU INTO A RAW PACKET -- HOWEVER, NOT USED --
	
    	printf("pdu:\nversion:%ld\ncommand:%d\n",pdu->version,pdu->command);
	
	
	//printf("Decoding done. \n ");
	printf("Decoding done. \n Now encoding");
	
	//return (pdu);
	
	status=snmp_build(&newpkt,&newpktlen,&offset,&session,pdu);
	printf("\nstatus = %d\n",status);
	printf("\nnewpktlen = %d\n",newpktlen);
	printf("\noffset = %d\n",offset);
	if(status==0)
	{
		//newpktlen=sizeof(newpkt);
		//printf("seems successful\n Here's the new packet:\npktlen :%d\n",newpktlen);
		printf("Packet dump : \n");
		for(ctr=newpktlen-offset;ctr<newpktlen;ctr++)
		{
			printf("%X",newpkt[ctr]);
		}	
		printf("\nPacket dump - END \n");
		for(ctr=newpktlen-offset,i=0;i<46 && ctr<newpktlen;i++,ctr++)
		{
			if(newpkt[ctr]!=pkt[i])
			{
				printf("\nMISMATCH");
				return(NULL);	
			}
		}
		printf("\nMATCH!!!!\n Parse successful\n");
		free(newpkt);
		newpkt = NULL;
		return pdu;
		
	}	
	else
	{
		printf("Parse failed");
		//free(newpkt);
		return (NULL);
	}
	
} 


/////////////////////////////

int forward(char *pkt,int pkt_len, struct in_addr ip,int command) // Final Packet forwarding function after all firewall rules are applied
{
	char *e;
	struct sockaddr_in servaddr;
	int sockfd;
	
	memset(&servaddr,0,sizeof(servaddr));
	
	servaddr.sin_family = PF_INET;
	
	if(command == SNMP_MSG_TRAP)
		servaddr.sin_port = htons(SNMPTRAP);
	else
		servaddr.sin_port = htons(SNMPNONTRAP);
	
	servaddr.sin_addr = ip;
	
	if((sockfd=socket(PF_INET,SOCK_DGRAM,0))<0)
	{	

		fputs("Socket Error\n",log);
		return(-1);
	}
	
	if(sendto(sockfd,pkt,pkt_len,0,(struct sockaddr *)&servaddr,sizeof(servaddr)) == -1)
	{
		e = strerror(errno);
		fputs(e,log);
		fputs("Send failed",log);
		return -1;
	}
		
	return 0;
}

int add_request(long reqid) // Store incoming Request ID in a list
{ 
	id_q *newnode;
	
	newnode=(id_q *)malloc(sizeof(id_q));
	if(newnode == NULL)
	{
		fputs("Malloc failed (add_request)",log);
		return -1;
	}
	
	newnode->next=NULL;
	newnode->reqid=reqid;
	newnode->myreqid = genmyreqid();
	
	if(id_head == NULL )
	{
		id_head = newnode;
	}
	else
	{
		newnode->next = id_head;	
		id_head = newnode;
	}
	
	return 0;

}

long chk_response(long reqid) //Check against New Request ID generated (myreqid)
{
	id_q *nownode,*prevnode;
	
	nownode = id_head;
	prevnode = id_head;
	for(;nownode != NULL;nownode=nownode->next)
	{
		if(reqid == nownode->myreqid)
		{
			prevnode->next = nownode->next;
			free(nownode);
			return nownode->reqid;	//FOUND
		}
		prevnode=nownode;
	}
	
	return 0;			//NOT FOUND

}

int chk_request(long reqid) //Check against Original Request ID (reqid)
{
	id_q *nownode;
	
	nownode = id_head;
	for(;nownode != NULL;nownode=nownode->next)
	{
		if(reqid == nownode->reqid)
		{
			return 0;	//FOUND
		}
	}
	
	return -1;			//NOT FOUND

}

int resend_packet(netsnmp_pdu *pdu,int sock) // Function creating Raw Packet form parsed PDU
{
	int status,ctr,i;
	size_t newpktlen=0,offset=0;
	u_char *newpkt,msg[MAXLINE];
	netsnmp_session session;
	struct in_addr ipaddr;
	
	newpktlen=0;
	offset=0;
	
	fputs("Forwarding packet : ",log);
	printf("\n ReqID : %ld", pdu->reqid);
	status=snmp_build(&newpkt,&newpktlen,&offset,&session,pdu);
	if(status==0)
	{
		fputs(" Encoding Successfull \n",log);
		fputs("Packet dump : \n",log);
		for(ctr=newpktlen-offset;ctr<newpktlen;ctr++)
		{
			msg[ctr+offset-newpktlen] = newpkt[ctr];
			sprintf(log_str,"%X",newpkt[ctr]);
			fputs(log_str,log);
		}	
		fputs("\nPacket dump - END \n",log);
		//free(newpkt);
		
		//GET IPADDR
		if(retreive(sock,&ipaddr))
		{
			fputs("Socket mapping retreival failed",log);
			return -1;
		}
		if(forward(msg,offset+1,ipaddr,pdu->command))
		{
			fputs(" Message Forwarding failed",log);
			return -1;
		}
		
		
		return 0;
	}
	else
	{
		fputs("Encoding Failed",log);
		//free(newpkt);
		return -1;
	
	}
	
}

int assess(netsnmp_pdu *pdu,int sock) // Function calling all functions that apply firewall rules
{
	long chngid;
	
	if(pdu->command == 160)	//GET
	{
		if(chk_request(pdu->reqid))
		{
			if (add_request(pdu->reqid))
				return (-1);
			else
				return (resend_packet(pdu,sock));
		}
		else
		{
			sprintf(log_str," Duplicate Request : Request Id : %ld",pdu->reqid);
			fputs(log_str,log);
			return (-1);
		}
	}
	else if(pdu->command == 162) //GETRESPONSE
	{
		chngid = chk_response(pdu->reqid);
		if(chngid)
		{
			pdu->reqid = chngid;	
			return resend_packet(pdu,sock);
		}
		else
		{
			sprintf(log_str," Unsolicited Respose : Request Id : %ld",pdu->reqid);
			fputs(log_str,log);
			return (-1);
		}
	}
	return 0;
}			

int barred(netsnmp_pdu *pdu)
{
	int ctr;
	for(ctr=0;ctr<10;ctr++)
	{
		if(pdu->command == barr[ctr])
		{
			sprintf(log_str," Message Type %d has been Barred : Dropping Packet \n",pdu->command);
			fputs(log_str,log);
			return -1;
		}
	}
	//fputs(pdu->community,log);
	return 0;
}

int config_init(void)
{
	char str1[20],str2[20],config_str[50];
	int num,ctr=0,read;
	int16_t port;
	FILE *config;
	int *tmp;
	
	if(mapper_init())
	{
		fputs("Mapper Failed",log);
		return -1;
	}
		
	config = fopen("/etc/appconfig.conf","r");
	if(config == NULL)
	{	
		fputs("Config file not found\n",log);
		//fclose(config);
		return -1;
	}
	else
	{	
		fputs("Config file found\n",log);
		sock_no = 1;
		sockfd = (int*)malloc(sizeof(int)*sock_no);
		sockfd[0]=0;
		while(!feof(config))
		{
			fgets(config_str,sizeof(config_str),config);
			//str=strstr(config_str,"restrict");
			
			read = sscanf(config_str,"%s %d",str1,&num);
			if(strcmp(str1,"restrict") == 0 && read == 2 && ctr < BARR_LENGTH)
			{
				barr[ctr++]=num;
				sprintf(log_str,"Restricting Message type : %d\n",num);
				fputs(log_str,log);
			}
			
			read = sscanf(config_str,"%s %s",str1,str2);
			if(strcmp(str1,"internip") == 0 && read == 2 && binder(0,str2,0))
			{	
				fputs(" Internal IP Address invalid",log); 
				fclose(config);
				return -1;
			}
			if(strcmp(str1,"externip") == 0 && read == 2 && binder(1,str2,0))
			{	
				fputs(" External IP Address invalid",log);
				fclose(config);
				return -1;
			}
			
			read = sscanf(config_str,"%s %d %s",str1,&port,str2);
			if(strcmp(str1,"internmap") == 0 && read == 3 && binder(2,str2,port))
			{
				sprintf(log_str," Internal Bind : port %d to %s failed\n",port,str2);
				fputs(log_str,log);
				fclose(config);
				return -1;
			}
			if(strcmp(str1,"externmap") == 0 && read == 3 && binder(3,str2,port))
			{
				sprintf(log_str," External Bind : port %d to %s failed\n",port,str2);
				fputs(log_str,log);
				fclose(config);
				return -1;
			}
			
		}
		fclose(config);
		return 0;
	}
	
}
int sock_add(int sock,int16_t port) // Add opened sockets to an array (used by select) 
{
	//sockfd = (int*)realloc(sockfd,++sock_no*(sizeof(int)))
	if(realloc(sockfd,(++sock_no)*sizeof(int)) == NULL)
	{	
		fputs("Realloc failed (config_init)",log);
		return -1;
	}
	else
	{
		sockfd[sock_no-1] = sockfd[sock_no-2];
		sockfd[sock_no-2] = sock;

		if(port>sockfd[sock_no-1])
			sockfd[sock_no-1] = port;
	}

	return 0;
}

int sock_bind(struct sockaddr_in servaddr, int16_t port) // Open listening ports
{
	//struct sockaddr_in servaddr;
	int sockfd;
	//struct in_addr ipaddr;
	
	servaddr.sin_port = htons(port);
	if((sockfd=socket(PF_INET,SOCK_DGRAM,0))<0)
	{	
		fputs("Socket Error\n",log);
		return(-1);
	}
	
	if(bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) != 0)
	{
		fputs("Bind Error\n",log);
		return(-1);
	}
	
	if(sock_add(sockfd,port) != 0)
	{
		fputs("Socket Update error",log);
		return (-1);
	}
		
	return sockfd;
	
}

int binder(int func,char *ipstr,int16_t port)
{
	static struct sockaddr_in internaddr,externaddr;
	struct in_addr ipaddr;
	int sockfd;
	//memset(&internaddr,0,sizeof(internaddr));
	//memset(&externaddr,0,sizeof(externaddr));
	internaddr.sin_family = PF_INET;
	externaddr.sin_family = PF_INET;
	
	switch(func)
	{
		case 0:
			if(inet_aton(ipstr,&ipaddr) == 0)
				return -1;
			else
				internaddr.sin_addr = ipaddr;
		break;
		
		case 1:
			if(inet_aton(ipstr,&ipaddr) == 0)
				return -1;
			else
				externaddr.sin_addr = ipaddr;
		break;
		
		case 2:
			sockfd = sock_bind(internaddr,port);
			if(sockfd == -1)
				return -1;
			else
				if(inet_aton(ipstr,&ipaddr) == 0)
				{	sprintf(log_str,"Intern IP Address map : %s invalid",ipstr);
					fputs(log_str,log);
					return -1;
				}
				else
					if(internmapper(sockfd,ipaddr))
						return -1;
		break;
			
		case 3:
			sockfd = sock_bind(externaddr,port); 
			if(sockfd== -1)
				return -1;
			else
				if(inet_aton(ipstr,&ipaddr) == 0)
				{	sprintf(log_str,"Extern IP Address map : %s  invalid",ipstr);
					fputs(log_str,log);
					return -1;
				}
				else
					if(externmapper(sockfd,ipaddr))
						return -1;
		break;
		
		default:
			return -1;
		break;
	}
	return 0;
}

uint32_t hash(uint32_t key) //ROBERT JETKINS HASH FUNCTION -- Maps Socket number(bound to specific port numbers) with IP Addresses
{
	key =  (key+0x7ed55d16) + (key<<12);
	key =  (key^0xc761c23c) + (key>>19);
	key =  (key+0x165667b1) + (key<<5);
	key =  (key+0xd3a2646c) + (key<<9);
	key =  (key+0xfd7046c5) + (key<<3);
	key =  (key+0xb55a4f09) + (key>>16);		

	key = key % MAXPORTSUPPORT;
	return key;
}

int mapper_init()
{
	externmap = (hash_map*)malloc(sizeof(hash_map)*MAXPORTSUPPORT);
	if(externmap == NULL)
	{
		fputs("Malloc failed (mapper_init)",log);
		return -1;
	}
	
	internmap = (hash_map*)malloc(sizeof(hash_map)*MAXPORTSUPPORT);
	if(internmap == NULL)
	{
		fputs("Malloc failed (mapper_init)",log);
		return -1;
	}
	return 0;
}

int externmapper(int sock,struct in_addr ipaddr) // Create HASH MAP
{
	uint32_t key;
	static int collide_no;
	hash_map *collide,*ptr;
	
	key = sock;
	key = hash(key) % MAXPORTSUPPORT;
	
	if(externmap[key].sock == 0)
	{
		externmap[key].ip = ipaddr;
		//externmap[key].port = port;
		externmap[key].sock = sock;
		externmap[key].next = NULL;
	}
	else
	{
		collide = (hash_map*)malloc(sizeof(hash_map));
		if(collide == NULL)
		{
			fputs("Malooc failed (mapper)",log);
			return -1;
		}
		for(ptr = &externmap[key];ptr->next != NULL;ptr = ptr->next);
		
		ptr->next = collide;
		
		collide->ip = ipaddr;
		//collide->port = port;
		collide->sock = sock;
		collide->next = NULL;
	}	
	

	return 0;
}

int internmapper(int sock,struct in_addr ipaddr) // Create HASH MAP
{
	uint32_t key;
	static int collide_no;
	hash_map *collide,*ptr;
	
	key = sock;
	key = hash(key);
	
	if(internmap[key].sock == 0)
	{
		internmap[key].ip = ipaddr;
		//internmap[key].port = port;
		internmap[key].sock = sock;
		internmap[key].next = NULL;
	}
	else
	{
		collide = (hash_map*)malloc(sizeof(hash_map));
		if(collide == NULL)
		{
			fputs("Malooc failed (mapper)",log);
			return -1;
		}
		for(ptr = &internmap[key];ptr->next != NULL;ptr = ptr->next);
		
		ptr->next = collide;
		
		collide->ip = ipaddr;
		//collide->port = port;
		collide->sock = sock;
		collide->next = NULL;
	}	
	

	return 0;
}
int retreive(int sock, struct in_addr *ip) // Retreive socket to IP address pair binding
{
	int key;
	struct in_addr ipaddr;
	hash_map *node;
	
	key = hash(sock);
	node = &internmap[key];
	
	do{
		if(sock == node->sock)
		{
			*ip =  node->ip;
			return 0;
		}
		else
			node = node->next;	
	
	}while(node != NULL);
	
	
	node = &externmap[key];
	do{
		if(sock == node->sock)
		{	
			*ip = node->ip;
			return 0;
		}
		else
			node = node->next;	
	
	}while(node != NULL);
	
	return -1;
}

long genmyreqid() // Generating a new Request ID (myreqid)
{
	static myreqid = 0;
	return (++myreqid);
}

/////////////////END OF PROGRAM///////////////////////////
/*

FILE : /etc/appconfig.conf -- Note : empty lines need to be entered at the end of file as the eof() function iterates on the last line twice !!!???

restrict 100
internip 127.0.0.2
externip 127.0.0.4

internmap 161 127.0.0.10
internmap 162 127.0.0.11

externmap 3001 127.0.0.12


------------------------------------
restrict <ASN1 PDU-TYPE>- Message Barred data types
externip <IP ADDRESS> - ip address to listen to the external network
internip <IP ADDRESS> - ip address to listen to the internal network

internmap <PORT NUMBER> <IP ADDRESS> - bind a listening port to an IP
externmap <PORT NUMBER> <IP ADDRESS> - bind a listening port to an IP


*/


