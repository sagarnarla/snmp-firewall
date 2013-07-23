#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

int main()
{
	u_char *pkt;
	size_t pktlen;
	netsnmp_pdu *pdu;
	
	pdu=(netsnmp_pdu *)calloc(1,sizeof(netsnmp_pdu));
	
	if(pdu)
	{
	       	pdu->version = SNMP_VERSION_1;
        	pdu->command = SNMP_MSG_RESPONSE;
       		pdu->errstat = SNMP_DEFAULT_ERRSTAT;
        	pdu->errindex = SNMP_DEFAULT_ERRINDEX;
        	
		pdu->securityModel = SNMP_DEFAULT_SECMODEL;
	
		pdu->enterprise_len=SNMP_DEFAULT_ENTERPRISE_LENGTH;
		pdu->time = SNMP_DEFAULT_TIME

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
		printf("Calloc Failed");
		return -1;
	}
	
		
