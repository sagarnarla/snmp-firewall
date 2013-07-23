#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>


size_t pktlen=46;
u_char pkt[46]={0x30,0x2C,0x02,0x01,0x00,0x04,0x07,0x70,0x72,0x69,0x76,0x61,0x74,0x65,0xA0,0x1E,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x03,0x30,0x13,0x30,0x11,0x06,0x0D,0x2B,0x06,0x01,0x04,0x01,0x94,0x78,0x01,0x02,0x07,0x03,0x02,0x00,0x05,0x00};
//u_char pkt[6]={0x30,0x2C,0x02,0x01,0x00,0x04};


int main(void)
{
	
	netsnmp_session session;
	netsnmp_pdu *pdu;
	netsnmp_variable_list *vars;
	int status=45,ctr;
   
	pdu = (netsnmp_pdu *) calloc(1, sizeof(netsnmp_pdu));
    	if (pdu) 
	{
        	pdu->version = SNMP_VERSION_1;
        	pdu->command = SNMP_MSG_RESPONSE;
       		pdu->errstat = SNMP_DEFAULT_ERRSTAT;
        	pdu->errindex = SNMP_DEFAULT_ERRINDEX;
        	pdu->securityModel = SNMP_DEFAULT_SECMODEL;
        	pdu->transport_data = NULL;
        	pdu->transport_data_length = 0;
        	pdu->securityNameLen = 0;
        	pdu->contextNameLen = 0;
        	pdu->time = 0;
        	pdu->reqid = snmp_get_next_reqid();
        	pdu->msgid = snmp_get_next_msgid();
    	}	
	
	printf("Message before parsing");
	for(ctr=0;ctr<pktlen;ctr++)
		printf("%x",pkt[ctr]);
	printf("\n\n");	
	
	status=snmp_parse(&session,pdu,pkt,pktlen);
	printf("Status %d",status);


	for(vars = pdu->variables; vars; vars = vars->next_variable)
        {
		print_variable(vars->name, vars->name_length, vars);
		printf("printing..");
	}
    
	return (0);
} 

