#ifndef _SERVERPACKET_H
#define _SERVERPACKET_H
#include <sys/types.h>


int sendOffer(struct dhcpMessage *oldpacket);
int sendNAK(struct dhcpMessage *oldpacket);
int sendACK(struct dhcpMessage *oldpacket, u_int32_t yiaddr);
int send_inform(struct dhcpMessage *oldpacket);


#endif
