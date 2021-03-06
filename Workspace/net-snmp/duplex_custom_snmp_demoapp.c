#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <stdlib.h>


size_t pktlen=72,newpktlen=0,offset=0;
/*
u_char pkt[46]=
{
0x30,0x2C,0x02,0x01,0x00,0x04,0x07,0x70,
0x72,0x69,0x76,0x61,0x74,0x65,0xA0,0x1E,
0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,
0x03,0x30,0x13,0x30,0x11,0x06,0x0D,0x2B,
0x06,0x01,0x04,0x01,0x94,0x78,0x01,0x02,
0x07,0x03,0x02,0x00,0x05,0x00
};


u_char pkt[44]=
{0x30,0x2A,0x02,0x01, 0x00,0x04,0x07,0x73, 0x69,0x65,0x6D,0x65,0x6E,0x73,0xA0,0x1C,   
 0x02,0x04,0x30,0x9E, 0xB9,0x0E,0x02,0x01, 0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C,   
 0x06,0x08,0x2B,0x06, 0x01,0x02,0x01,0x01, 0x06,0x00,0x05,0x00};


u_char pkt[72]=
{0x30,0x46,0x02,0x01,0x00,0x04,0x07,0x73,0x69,0x65,0x6D,0x65,0x6E,0x73,0xA0,0x38,
0x02,0x04,0x3C,0x4B,0x18,0x96,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x2A,0x30,0x0C,
0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00,0x30,0x0C,0x06,0x08,
0x2B,0x06,0x01,0x02,0x01,0x01,0x06,0x00,0x05,0x00,0x30,0x0C,0x06,0x08,0x2B,0x06,
0x01,0x02,0x01,0x01,0x04,0x00,0x05,0x00};
*/

u_char pkt[48]=
{0x30,0x2E,0x02,0x01,0x00,0x04,0x07,0x73,0x69,0x65,0x6D,0x65,0x6E,0x73,0xA3,0x20
,0x02,0x04,0x17,0x8B,0x35,0xE9,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x12,0x30,0x10
,0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x04,0x00,0x04,0x04,0x64,0x67,0x30,0x61};

u_char *newpkt;

int main(void)
{
	
	netsnmp_session session;
	netsnmp_pdu *pdu;
	netsnmp_variable_list *vars;
	int status=45,ctr,i;
   
	pdu = (netsnmp_pdu *) calloc(1, sizeof(netsnmp_pdu));
    	if (pdu) 
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
	
	printf("Message before parsing\n");
	for(ctr=0;ctr<pktlen;ctr++)
		printf("%x",pkt[ctr]);
	printf("\n\n");	
	
	status=snmp_parse(&session,pdu,pkt,pktlen);
	printf("Status %d",status);


	for(vars = pdu->variables; vars; vars = vars->next_variable)
        {
		print_variable(vars->name, vars->name_length, vars);
		
	}
    	printf("pdu:\nversion:%ld\ncommand:%d\n",pdu->version,pdu->command);
	
	
	printf("Decoding done. \n Now encoding...");
	
	status=snmp_build(&newpkt,&newpktlen,&offset,&session,pdu);
	printf("\nstatus = %d\n",status);
	printf("\nnewpktlen = %d\n",newpktlen);
	printf("\noffset = %d\n",offset);
	if(status==0 || status==-20)
	{
		//newpktlen=sizeof(newpkt);
		//printf("seems successful\n Here's the new packet:\npktlen :%d\n",newpktlen);
		printf("Packet dump : \n");
		for(ctr=newpktlen-offset;ctr<newpktlen;ctr++)
		{
			printf("%X",newpkt[ctr]);
		}	
		printf("\nPacket dump - END \n");
		for(ctr=newpktlen-offset,i=0;i<pktlen && ctr<newpktlen;i++,ctr++)
		{
			if(newpkt[ctr]!=pkt[i])
			{
				printf("\nMISMATCH");
				exit(1);	
			}
		}
		printf("\nMATCH!!!!\n Parse successful\n");
	}	

	
	
	
	return (0);
} 

