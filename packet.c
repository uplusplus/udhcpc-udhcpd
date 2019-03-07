#include <unistd.h>
#include "stdbool.h"
#include "stdint.h"
#include <stdlib.h>
#include <endian.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <features.h>
#if __GLIBC__ >=2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif
#include <errno.h>

#include "packet.h"
#include "debug.h"
#include "dhcpd.h"
#include "options.h"

#include "stb_3des.h"
#include "md5.h"


typedef struct _V_field_opt60{
    char magic[3];
    char length;
    char _O;
    uint64_t randomn;
    uint64_t timestamp;
    char md5sum[16];
    char context[0];
}__attribute__ ((packed)) stu_val_opt60;


extern const char *username;
extern const char *password;

static int generate_option60_common(stu_val_opt60* ori_text, int lens, char* outbuf, bool sw)
{
	const char *user = username;
	const char *passwd = password;

	//use O=1 to describe this algorithms.
	int _O = 1;
	unsigned char timestamp[9] = {0};
	unsigned char random_number[9] = {0};
	uint64_t ts = 0;
	uint64_t rd = 0;
	unsigned char context[25] = {0};

	char ciphertext[24] = {0};
	unsigned char md5text[129] = {0};
	unsigned char md5out[17]={0};
	int len;
	int md5len = 0;
	void* handle = NULL;
	int outbuf_len = 0;

    if (sw) LOG(LOG_DEBUG, "random = 0x%llx(%d)", htobe64(ori_text->randomn), sizeof(stu_val_opt60));
    if (sw) LOG(LOG_DEBUG, "timest = 0x%llx(%lld)", htobe64(ori_text->timestamp),htobe64(ori_text->timestamp));
	rd = (ori_text->randomn);
	ts = (ori_text->timestamp);
    if (sw) LOG(LOG_DEBUG, "begining memset...");


	//context = 3des_enrypt(R + user + TS)
	memset(ciphertext,0,sizeof(ciphertext));
	memcpy(ciphertext,&rd,8);
	memcpy(ciphertext+8,&ts,8);
    if (sw) LOG(LOG_DEBUG, "begining HS_3des_encrypt...");
	len = HS_3des_encrypt(ciphertext,(unsigned char*)user,context);

    char tmp1[len*5];
    memset(tmp1, 0, len*5);
    for(int i=0; i<len; i++) {
        sprintf(tmp1+i*5, "0x%02x ", context[i]);
    }
    LOG(LOG_DEBUG,"context: %s",tmp1);

	//KEY = md5(R + passwd + TS)
	memset(md5text,0,sizeof(md5text));
	memcpy(md5text,&rd,8);
	md5len = 8;
	memcpy(md5text+md5len,passwd,strlen(passwd));
	md5len +=strlen(passwd);
	memcpy(md5text+md5len,&ts,8);
	md5len += 8;
    if (sw) LOG(LOG_DEBUG, "begining STB_digest_init...");
	//handle = STB_digest_init(STB_DIGEST_MD5);
	//STB_digest_update(handle,md5text,md5len);
	//STB_digest_final(handle, md5out, 16);
    
    Md5Handler(&handle, MD5_INIT, NULL, 0);
    Md5Handler(&handle, MD5_UPDATE, md5text, md5len);
    Md5Handler(&handle, MD5_FINAL, md5out, 0);

    char tmp2[md5len*5];
    memset(tmp2, 0, md5len*5);
    for(int i=0; i<md5len; i++) {
        sprintf(tmp2+i*5, "0x%02x ", md5out[i]);
    }
    LOG(LOG_DEBUG,"md5out: %s",tmp2);

	//opption60 = O + R + TS + KEY + context
	memset(outbuf,_O,1);
	outbuf_len +=1;
	memcpy(outbuf+outbuf_len,&rd,8);
	outbuf_len +=8;
	memcpy(outbuf+outbuf_len,&ts,8);
	outbuf_len += 8;
	memcpy(outbuf+outbuf_len,md5out,16);
	outbuf_len += 16;
	memcpy(outbuf+outbuf_len,context,len);
	outbuf_len += len;


	if (sw) LOG(LOG_DEBUG, "generate option60 method: out %d bytes", outbuf_len);
    char tmp3[outbuf_len*5];
    memset(tmp3, 0, outbuf_len*5);
    for(int i=0; i<outbuf_len; i++) {
        sprintf(tmp3+i*5, "0x%02x ", outbuf[i]);
    }

    LOG(LOG_DEBUG,"outbuf: %s",tmp3);

	return outbuf_len;
}

bool validation_opt60(unsigned char* ciphertext, int len, bool sw) {
    char sum_by_self_buf_out[256] = {0};
    int sum_self_len = generate_option60_common((stu_val_opt60*) ciphertext, len, sum_by_self_buf_out, sw);
    // not equals
    if(memcmp(&(((stu_val_opt60*)ciphertext)->_O), sum_by_self_buf_out, sum_self_len>256?256:sum_self_len)) {
        LOG(LOG_ERR, "not equals");
        return false;
    }
    return true;
}

void init_header(struct dhcpMessage *packet, char type)
{
	memset(packet, 0, sizeof(struct dhcpMessage));
	switch (type) {
	case DHCPDISCOVER:
	case DHCPREQUEST:
	case DHCPRELEASE:
	case DHCPINFORM:
		packet->op = BOOTREQUEST;
		break;
	case DHCPOFFER:
	case DHCPACK:
	case DHCPNAK:
		packet->op = BOOTREPLY;
	}
	packet->htype = ETH_10MB;
	packet->hlen = ETH_10MB_LEN;
	packet->cookie = htonl(DHCP_MAGIC);
	packet->options[0] = DHCP_END;
	add_simple_option(packet->options, DHCP_MESSAGE_TYPE, type);
}


/* read a packet from socket fd, return -1 on read error, -2 on packet error */
int get_packet(struct dhcpMessage *packet, int fd)
{
	int bytes;
	int i;
	const char broken_vendors[][8] = {
		"MSFT 98",
		""
	};
	char unsigned *vendor;

	memset(packet, 0, sizeof(struct dhcpMessage));
	bytes = read(fd, packet, sizeof(struct dhcpMessage));
	if (bytes < 0) {
		DEBUG(LOG_INFO, "couldn't read on listening socket, ignoring");
		return -1;
	}

	if (ntohl(packet->cookie) != DHCP_MAGIC) {
		LOG(LOG_ERR, "received bogus message, ignoring");
		return -2;
	}
	DEBUG(LOG_INFO, "+++++++++++++++  Received a packet +++++++++++++++++");
	
	if (packet->op == BOOTREQUEST && (vendor = get_option(packet, DHCP_VENDOR))) {
		for (i = 0; broken_vendors[i][0]; i++) {
			if (vendor[OPT_LEN - 2] == (unsigned char) strlen(broken_vendors[i]) &&
			    !strncmp(vendor, broken_vendors[i], vendor[OPT_LEN - 2])) {
			    	DEBUG(LOG_INFO, "broken client (%s), forcing broadcast",
			    		broken_vendors[i]);
			    	packet->flags |= htons(BROADCAST_FLAG);
			}
		}
	}
			    	

	return bytes;
}


u_int16_t checksum(void *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register int32_t sum = 0;
	u_int16_t *source = (u_int16_t *) addr;

	while (count > 1)  {
		/*  This is the inner loop */
		sum += *source++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if (count > 0) {
		/* Make sure that the left-over byte is added correctly both
		 * with little and big endian hosts */
		u_int16_t tmp = 0;
		*(unsigned char *) (&tmp) = * (unsigned char *) source;
		sum += tmp;
	}
	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}


/* Construct a ip/udp header for a packet, and specify the source and dest hardware address */
int raw_packet(struct dhcpMessage *payload, u_int32_t source_ip, int source_port,
		   u_int32_t dest_ip, int dest_port, unsigned char *dest_arp, int ifindex)
{
	int fd;
	int result;
	struct sockaddr_ll dest;
	struct udp_dhcp_packet packet;

	if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
		DEBUG(LOG_ERR, "socket call failed: %s", strerror(errno));
		return -1;
	}
	
	memset(&dest, 0, sizeof(dest));
	memset(&packet, 0, sizeof(packet));
	
	dest.sll_family = AF_PACKET;
	dest.sll_protocol = htons(ETH_P_IP);
	dest.sll_ifindex = ifindex;
	dest.sll_halen = 6;
	memcpy(dest.sll_addr, dest_arp, 6);
	if (bind(fd, (struct sockaddr *)&dest, sizeof(struct sockaddr_ll)) < 0) {
		DEBUG(LOG_ERR, "bind call failed: %s", strerror(errno));
		close(fd);
		return -1;
	}

	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.saddr = source_ip;
	packet.ip.daddr = dest_ip;
	packet.udp.source = htons(source_port);
	packet.udp.dest = htons(dest_port);
	packet.udp.len = htons(sizeof(packet.udp) + sizeof(struct dhcpMessage)); /* cheat on the psuedo-header */
	packet.ip.tot_len = packet.udp.len;
	memcpy(&(packet.data), payload, sizeof(struct dhcpMessage));
	packet.udp.check = checksum(&packet, sizeof(struct udp_dhcp_packet));
	
	packet.ip.tot_len = htons(sizeof(struct udp_dhcp_packet));
	packet.ip.ihl = sizeof(packet.ip) >> 2;
	packet.ip.version = IPVERSION;
	packet.ip.ttl = IPDEFTTL;
	packet.ip.check = checksum(&(packet.ip), sizeof(packet.ip));

	result = sendto(fd, &packet, sizeof(struct udp_dhcp_packet), 0, (struct sockaddr *) &dest, sizeof(dest));
	if (result <= 0) {
		DEBUG(LOG_ERR, "write on socket failed: %s", strerror(errno));
	}
	close(fd);
	return result;
}


/* Let the kernel do all the work for packet generation */
int kernel_packet(struct dhcpMessage *payload, u_int32_t source_ip, int source_port,
		   u_int32_t dest_ip, int dest_port)
{
	int n = 1;
	int fd, result;
	struct sockaddr_in client;
	
	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return -1;
	
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1)
		return -1;

	memset(&client, 0, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_port = htons(source_port);
	client.sin_addr.s_addr = source_ip;

	if (bind(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
		return -1;

	memset(&client, 0, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_port = htons(dest_port);
	client.sin_addr.s_addr = dest_ip; 

	if (connect(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
		return -1;

	result = write(fd, payload, sizeof(struct dhcpMessage));
	close(fd);
	return result;
}	

