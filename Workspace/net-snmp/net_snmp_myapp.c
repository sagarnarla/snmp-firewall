#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>


//#define PKTLEN 46

int main()
{
	int err;	

	struct snmp_pdu *pdu;
	netsnmp_session session,*ss; //For error and versioning

	size_t pktlen=43;
	//u_char pkt[43];
	u_char pkt[43]={0x30,0x2C,0x02,0x01,0x00,0x04,0x07,0x70,0x72,0x69,0x76,0x61,0x74,0x65,0xA0,0x1E,0x02,0x01,0x01,0x02,0x01,0x00,0x30,0x13,0x30,0x11,0x06,0x0D,0x2B,0x06,0x01,0x04,0x01,0x94,0x78,0x01,0x02,0x07,0x03,0x02,0x00,0x05,0x00};
	
   	
	//init_snmp("snmpdemoapp");

	snmp_sess_init( &session );  
    	//session.peername = strdup("test.net-snmp.org");	

	session.version = SNMP_VERSION_1;

	session.community = "demopublic";
	session.community_len = strlen(session.community);


	 ss = snmp_open(&session);
	pdu = snmp_pdu_create(SNMP_RSP_MSG);

	err=snmp_parse(session,pdu,pkt,pktlen);

	printf("Return value:%d",err);
	
	return 0;
}	
	
	
	
	
	




	
