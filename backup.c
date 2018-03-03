#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netdb.h>

#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define TYPE 2
#define LEN 1
#define OPCODE 2
#define EH_LENGTH 14
#define IP_H_LEN 20
#define HW_TYPE 1


/* Check sum function */
unsigned short chsum(unsigned short *buf, int count);
unsigned short myChecksum(unsigned char *packet, int length);

int main(int argc, char** argv) {
    /* Create selector. */
    fd_set sockets;
    FD_ZERO(&sockets);
    /* Keep track of the socket we are using. */
    int currentSocket;
    /* Keep a record of interfaces this router holds. */
    int MAX_INTERFACE;
    /* Keep a record of forwarding addresses this router holds in forwarding table. */
    int MAX_TABLE;
	
	//Timer
	//struct timeval timeout;
    //timeout.tv_sec = 0;
    //timeout.tv_usec = 100000;
    
    struct ifaddrs *ifaddr, *tmp;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }
    /*creating struct */
    struct interface {
        char ip[IPV4_LENGTH];    // 4 bytes interface ip addr
        char mac[MAC_LENGTH];    // 6 bytes interface mac addr
        char name[8];           // 8 bytes interface name
        int packetSocket;
    };
    /* Instantiate an array of interfaces struct. */
    struct interface pairs[10];
    /* Used to loop the interface so we can store the information. */
    int readInterface = 0;
    //have the list, loop over the list.
    printf("Router Start\n");
    for (tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next) {
        /************************************************************
         * Extract MAC Addr.
         ***********************************************************/
        if (tmp->ifa_addr->sa_family == AF_PACKET) {
            //create a packet socket on interface r?-eth1.
            if (!strncmp(&(tmp->ifa_name[3]), "eth", 3)) {
                // Store the interface name into the array of structs.
                memcpy(&pairs[readInterface].name, tmp->ifa_name, 8);
                printf("Creating Socket on interface %s\n", tmp->ifa_name);
                // connects the packet socket to the interface.
                pairs[readInterface].packetSocket = socket(AF_PACKET, SOCK_RAW,htons(ETH_P_ALL));
                if (pairs[readInterface].packetSocket < 0) {
                    perror("socket");
                    return 2;
                }
                char *printmac;
                /* Create a link layer struct. */
                struct sockaddr_ll *mymac = (struct sockaddr_ll*) tmp->ifa_addr;
                // Store the source mac into the array of struct.
                memcpy(&pairs[readInterface].mac, &mymac->sll_addr, 6);
                printmac = ether_ntoa((struct ether_addr*) &pairs[readInterface].mac);
                printf("\tName: %s MAC: %s\n", tmp->ifa_name, printmac);
                // Bind the interface to a socket
                if (bind(pairs[readInterface].packetSocket, tmp->ifa_addr,sizeof(struct sockaddr_ll)) == -1) {
                    perror("bind error");
                }
                // Set the packet socket to the selector.
                FD_SET(pairs[readInterface].packetSocket, &sockets);
                readInterface++;
                // Count the number of interfaces.
                MAX_INTERFACE=readInterface;
            }
        }
        /************************************************************
         * Extract IP addr if packet is AF_INET.
         ***********************************************************/
        if (tmp->ifa_addr->sa_family == AF_INET) {
            int loop;
            for (loop = 0; loop < 10; loop++) {
                if (!strncmp(&(tmp->ifa_name[3]), &pairs[loop].name[3], 4)
                    && !strncmp(&pairs[loop].name[3], "eth", 3)) {
                    struct sockaddr_in *sa;
                    char *printip;
                    sa = (struct sockaddr_in*) tmp->ifa_addr;
                    memcpy(&pairs[loop].ip, &sa->sin_addr.s_addr, 4);
                    printip = inet_ntoa(*(struct in_addr*) &pairs[loop].ip);
                    printf("Name: %s IP:<%s>\n", pairs[loop].name, printip);
                }
            }
        }
    }
    /* This loop simply print out all the interfaces of the router. */
    printf("\n\n");
    int printcheck = 0;
    for (printcheck = 0; printcheck < MAX_INTERFACE; printcheck++) {
        if (!strncmp(&pairs[printcheck].name[3], "eth", 3)) {
            printf("Interface: %s", pairs[printcheck].name);
            printf("\tIP Address: %s",
                   inet_ntoa(*(struct in_addr*) pairs[printcheck].ip));
            printf("\tMAC Address: %s",
                   ether_ntoa((struct ether_addr*) pairs[printcheck].mac));
            printf("\tSocket: %d\n", pairs[printcheck].packetSocket);
        }
    }
    // Set the table size (number of rows).
    MAX_TABLE=MAX_INTERFACE+1;
    /***************************************************************
     * SETTING UP FORWARDING TABLE.
     *****************************************************************/
    char entire_row1[200];
    /* Creating struct for storing forwarding information. */
    struct forward{
        char ip[100];
        char match[3];
        int bitMatch;
        char ip2[12];
        char name[8];
    };
    FILE *reads;
    char filename[40];
    /* Instantiating a File based on user input. */
    printf("\nType in name of the forwarding table\n");
    scanf("%s",&filename);
    reads=fopen(filename, "r");
    if (reads==NULL) {
        perror("Error");
        return 1;
    }
    /*File instantiated now reading contents into a array of forwards. */
    int nav = 0;
    int current = 0;
    int fNO = 0;
    int setsize = MAX_TABLE;
    struct forward forwardTable[5];
    while (nav < MAX_TABLE){
        current = 0;
        fNO = 0;
        fgets(entire_row1, 60, reads);
        // getting the IP
        while(entire_row1[current] != '/'){
            forwardTable[nav].ip[fNO] = entire_row1[current];
            current++;
			fNO++;
        }
        current++;
        fNO=0;
        // getting the number of bits that must match.
        while(fNO < 2){
            forwardTable[nav].match[fNO] = entire_row1[current];
            current++;fNO++;
        }
        forwardTable[nav].bitMatch = atoi(forwardTable[nav].match); // converting to an int.
        current++;
        fNO=0;
        // getting the second IP if applicable.
        while(entire_row1[current] != ' '){
            forwardTable[nav].ip2[fNO] = entire_row1[current];
            current++;fNO++;
        }
        current++;
        fNO=0;
        // getting the interface name from forwarding table.
        while(entire_row1[current] != '\n'){
            forwardTable[nav].name[fNO] = entire_row1[current];
            current++;fNO++;
        }
        current++;
        fNO=0;
        nav++;
    }
    /* Printing the contents of the array of forwards */
    int q = 0;
    while (q<MAX_TABLE) {
        printf("In the Struct: %s %d %s  %s \n", forwardTable[q].ip,forwardTable[q].bitMatch,forwardTable[q].ip2,forwardTable[q].name);
        q++;
    }
    /*********************************************************
     * FINISHED SETTING UP FORWARDING TABLE.
     ********************************************************/
    printf("\n\nReady to recieve now\n\n");
    while (1) {
        /* This buffer holds the newest packet received. */
        char buf[1500];
        /* This buffer holds the last forwarding packet recieved. */
        char forward_buf[1500];
        struct sockaddr_ll recvaddr;
        int recvaddrlen = sizeof(struct sockaddr_ll);
        fd_set temp_set = sockets;
        select(FD_SETSIZE, &temp_set, NULL, NULL, NULL);
        int i;
        int arpRequested = 0;
        for (i = 0; i < 5; i++) {
            /* Checking which socket packet arrives on. */
            if (FD_ISSET(pairs[i].packetSocket, &temp_set)) {
                currentSocket = i;
                printf("currentSocket = %d\n", currentSocket);
                int n = recvfrom(pairs[i].packetSocket, buf, 1500, 0,
                                 (struct sockaddr*) &recvaddr, &recvaddrlen);
                if (n == -1) {
                    printf("fail");
                }
                // Ignore outgoing packets.
                if (recvaddr.sll_pkttype == PACKET_OUTGOING)
                    continue;
                printf("Got a %d byte packet\n", n);
                /* Store the packet as an Arp packet. */
                struct ether_header *arp_eh = (struct ether_header*) buf;
                struct ether_arp *arp_req =(struct ether_arp*)(buf + EH_LENGTH);
                short arptype = ntohs(arp_req->ea_hdr.ar_op);
                
                /* Store the packet as an ICMP packet. */
                struct ether_header *icmp_eh = (struct ether_header*) buf;
                struct iphdr *ip = (struct iphdr*) (buf + EH_LENGTH);
                struct icmphdr *icmp = (struct icmphdr*) (buf+IP_H_LEN+EH_LENGTH);
                uint8_t ictype = icmp->type;
                
                /* Store the destination IP of current packet if its an IP packet. */
                char *print;
                char *tem_ip;
				char *compareIP;
                tem_ip = inet_ntoa(*(struct in_addr*) &ip->daddr);
				memcpy(&compareIP,&tem_ip,10);
                if(arptype!=ARPOP_REQUEST||arptype!=ARPOP_REPLY){ // PRINT IP DESTINATION FOR IP OR ICMP PACKET
                    printf("Destination IP: %s\n", tem_ip);
                }else{ // CHECK IF THE PACKET IS AN ARP PACKET
                    printf("Receive an ARP packet: %x\n", arptype);
                }
                /* Ignore all packet sent local */
                if(!strncmp(&tem_ip[0], "127.0.0.1", 9)){
                    //printf("Local packet--Ignored\n");
                    continue;
                }
                /* Used to determine forwarding packets */
                int forwardingSocket = -1;
                /* Used to determine incoming packets */
                int incomingPacket = -1;
                /* Used to keep track of next ip hop */
                u_int32_t ip_hop;
                printf("ICMP Type: %d\n", ictype);
                /************************************************************
                 * Reply a arp response if received a request.
                 ***********************************************************/
                if (arptype == ARPOP_REQUEST) {
                    printf("Received ARP request!\n");
                    /************************************************************
                     * Modify the etherheader and store the necessary values
                     ***********************************************************/
                    memcpy(&arp_eh->ether_dhost, &arp_eh->ether_shost,
                           MAC_LENGTH);
                    memcpy(&arp_eh->ether_shost, &pairs[currentSocket].mac,
                           MAC_LENGTH);
                    /************************************************************
                     * Modift the ARP header and store the necessary values
                     ***********************************************************/
                    // modify opcode
                    arp_req->ea_hdr.ar_op = htons(ARPOP_REPLY);
                    // modify target mac
                    memcpy(&arp_req->arp_tha, &arp_req->arp_sha, MAC_LENGTH);
                    // modify target ip
                    memcpy(&arp_req->arp_tpa, &arp_req->arp_spa, IPV4_LENGTH);
                    // modify source mac
                    memcpy(&arp_req->arp_sha, &pairs[currentSocket].mac,MAC_LENGTH);
                    // modify src ip
                    memcpy(&arp_req->arp_spa, &pairs[currentSocket].ip,IPV4_LENGTH);
                    // print out src and dst mac for verification.
                    char *print;
                    print = ether_ntoa((struct ether_addr*) &arp_req->arp_sha);
                    printf("\tARP Reply Source MAC: %s\n", print);
                    print = ether_ntoa((struct ether_addr*) &arp_req->arp_tha);
                    printf("\tARP Reply Destination MAC: %s\n", print);
                    // Send the arp reply packet back
                    send(pairs[currentSocket].packetSocket, buf, 42, 0);
                    printf("-------------Sent ARP Reply-------------\n");
                }
                /************************************************************
                 * Check the IP to see if the packet can be forwarded
                 ***********************************************************/
                if (strncmp(&tem_ip[0], "10.0.0", 6)) { // FORWARDING PACKET, NOT FOR THIS ROUTER
                    int loopF;
                    for (loopF = 0; loopF < MAX_TABLE; loopF++) {
                        int bit = forwardTable[loopF].bitMatch / 4;
                        if (!strncmp(&forwardTable[loopF].ip[0], &tem_ip[0],bit)) {
			  ip_hop = ip->daddr;
			
			short recvCheck=ip->check;
			  printf("Received Checksum:%x\n", ip->check);
			  ip->check=0x0000;
				short *storeCheck;
			  memcpy(&storeCheck,&ip,20);
				short calcCheck=chsum(storeCheck,10);
				if(calcCheck!=recvCheck){
					continue;
			}
	memcpy(&ip->check,&calcCheck,2);

			  printf("New: %x \n", calcCheck);

			  if (!strncmp(&forwardTable[loopF].name[3], "eth0",4)) {
			    ip_hop = inet_addr(forwardTable[loopF].ip2);
			  }
			  /* Decrease the ttl everytime. */
			  //ip->ttl--;
			  int loopName;
			  /* Loop the interfaces to set the destintion socket we want to use */
			  for (loopName = 0; loopName < MAX_TABLE; loopName++) {
			    if (!strncmp(&forwardTable[loopF].name[0],&pairs[loopName].name[0], 8)) {
			      forwardingSocket = loopName;
			    }
			  }
                        }
                    }
                }

                /************************************************************
                 * Check the IP to see if the packet is for this router.
                 ***********************************************************/
	//char *tempIp=inet_ntoa(*(struct in_addr*) &ip->daddr);
	
		int loopCheckI;
		for (loopCheckI = 0; loopCheckI < MAX_INTERFACE; loopCheckI++) {
		  //char *tempCmpIp=inet_ntoa(*(struct in_addr*) pairs[loopCheckI].ip);
			//printf("interip: %s\n",tempCmpIp);
			
			//printf("sendIp:%s\n",compareIP);
			char tempI[4];
			memcpy(&tempI,&ip->daddr,4);
		  if (!strncmp(pairs[loopCheckI].ip,tempI,4)){
			printf("count%d\n",loopCheckI);
		    incomingPacket=loopCheckI;
		  }
		}
		printf("incoming: %d, forwarding: %d\n", incomingPacket, forwardingSocket);
                /******************************************************************************
                 * Checks if destination is reachable from our router or not.
                 *****************************************************************************/
                if((forwardingSocket == -1 && incomingPacket==-1) || ip->ttl==0) { // SEND ICMP DEST UNREACHABLE.
		  printf("Ready to sent ICMP Error\n");
		  char icmp_unreach[42];
		  /************************************************************
		   * Instantiate an ether header and store the necessary values
		   ***********************************************************/
		  struct ether_header destUnreach_eh;
		  /* Store our dst MAC to the 0-5 byte. */
		  memcpy(&destUnreach_eh.ether_dhost, &icmp_eh->ether_shost,MAC_LENGTH);
		  print = ether_ntoa((struct ether_addr*) &destUnreach_eh.ether_dhost);
		  printf("\nDest Ether: %s \n", print);
		  
		  /* Store our sour mac to the 6-11 byte. */
		  memcpy(&destUnreach_eh.ether_shost, &pairs[forwardingSocket].mac,MAC_LENGTH);
		  // Checks if value is copied correctly
		  print = ether_ntoa((struct ether_addr*) &destUnreach_eh.ether_shost);
		  printf("\nSource Ether: %s\n", print);
                  
		  /* Store our ether type to the 12-13 byte. */
		  destUnreach_eh.ether_type = htons(ETH_P_IP);
		  // Checks if value is copied correctly
		  short etype = ntohs(destUnreach_eh.ether_type);
		  printf("\nEther Type: %x\n", etype);

		  /************************************************************
		   * Modify source and desination IP in IP header
		   ***********************************************************/
		  struct iphdr error_ip;
		  memcpy(&error_ip.tos, &ip->tos, LEN);
		  memcpy(&error_ip.tot_len, &ip->tot_len, 2);
		  memcpy(&error_ip.id, &ip->id, 2);
		  memcpy(&error_ip.frag_off, &ip->frag_off, 2);
		  memcpy(&error_ip.ttl, &ip->ttl, 1);
		  memcpy(&error_ip.protocol, &ip->protocol, 1);

		  memcpy(&error_ip.saddr, &pairs[currentSocket].ip, IPV4_LENGTH);
		  memcpy(&error_ip.daddr, &ip->saddr, IPV4_LENGTH);

		error_ip.check=0x0000;
				short storeCheck[10];
			  memcpy(&storeCheck,&error_ip,20);
				short calcCheck=chsum(storeCheck,10);
			error_ip.check = calcCheck;

		  /************************************************************
		   * Modify ICMP type to destination unreachable.
		   ***********************************************************/
		  struct icmphdr icmp_un;
		  icmp_un.type = htons(ICMP_DEST_UNREACH);
		  icmp_un.code = htons(ICMP_NET_UNREACH);
		  if(ip->ttl=0){
		    icmp_un.type = htons(ICMP_TIME_EXCEEDED);
		    icmp_un.code = htons(ICMP_EXC_TTL);
		  }
			icmp_un.checksum=0x0000;

		  memcpy(&icmp_unreach[0],&destUnreach_eh,12);
		  memcpy(&icmp_unreach[12],&error_ip,20);
		  memcpy(&icmp_unreach[32],&icmp_un,8);
		  memcpy(&icmp_unreach[40],&forward_buf[12],28);

			
			
			memcpy(&storeCheck,&icmp_unreach[32],36);
			calcCheck=chsum(storeCheck,18);
			icmp_un.checksum = calcCheck;

		 	memcpy(&icmp_unreach[32],&icmp_un,8);
		  send(pairs[currentSocket].packetSocket, icmp_unreach, 68, 0);
		  printf("-------------Sent ICMP Destination Unreachable-------------\n");
			continue;
                }
                /******************************************************************************
                 * Checks if the packet destination is the router IP.
                 * Sends back ICMP packet if it's router's packet.
                 *****************************************************************************/
                if(incomingPacket!=-1){ // PACKET DESTINATION IS THE CURRENT ROUTER
		  printf("\nIncoming Packets\n");
		  /************************************************************
		   * Checks if the packet is ICMP packet
		   ***********************************************************/
		  if (ictype == ICMP_ECHO) {
		    printf("\tReceived ICMP ECHO request!\n");
		    /************************************************************
		     * Modify source and desination mac in etherheader
		     ***********************************************************/
		    memcpy(&icmp_eh->ether_dhost, &icmp_eh->ether_shost,MAC_LENGTH);
		    memcpy(&icmp_eh->ether_shost, &pairs[currentSocket].mac,MAC_LENGTH);
		    /************************************************************
		     * Modify source and desination IP in IP header
		     ***********************************************************/
		    memcpy(&ip->daddr, &ip->saddr, IPV4_LENGTH);
		    memcpy(&ip->saddr, &pairs[currentSocket].ip, IPV4_LENGTH);
		    /************************************************************
		     * Modify ICMP type.
		     ***********************************************************/
		    icmp->type = htons(ICMP_ECHOREPLY);



			short recvCheck=icmp->checksum;
			printf("Old: %x \n", icmp->checksum);
			icmp->checksum=0x0000;
			short *storeCheck;
			memcpy(&storeCheck,&icmp,12);
			short calcCheck=chsum(storeCheck,6);
			printf("New: %x \n", calcCheck);
			if(calcCheck!=recvCheck){
				printf("Not matched");
				continue;
			}
			memcpy(&icmp->checksum,&calcCheck,2);

		    printf("-------------Sent ICMP Echo Reply-------------%d\n",currentSocket);
		    send(pairs[currentSocket].packetSocket, &buf, 1500, 0);
		  }
		}
                /************************************************************
                 * Constructing an ARP request to the next hop.
                 ***********************************************************/
                if(forwardingSocket != -1){ // PACKET DESTINATION IS IN THE FORWARDING TABLE
                    
                    printf("\nForwarding Arp: %d\n", forwardingSocket);
                    // Store the current packet into a forwarding buffer for later use
                    memcpy(&forward_buf, &buf, 1500);
                    /************************************************************
                     * Instantiate an ether header and store the necessary values
                     ***********************************************************/
                    struct ether_header send_eth;
                    /* Store our dst MAC to the 0-5 byte. */
                    memset(send_eth.ether_dhost, 0xff, MAC_LENGTH);
                    print = ether_ntoa((struct ether_addr*) &send_eth.ether_dhost);
                    printf("\nDest Ether: %s \n", print);
                    
                    /* Store our sour mac to the 6-11 byte. */
                    memcpy(&send_eth.ether_shost, &pairs[forwardingSocket].mac,MAC_LENGTH);
                    // Checks if value is copied correctly
                    print = ether_ntoa((struct ether_addr*) &send_eth.ether_shost);
                    printf("\nSource Ether: %s\n", print);
                    
                    /* Store our ether type to the 12-13 byte. */
                    send_eth.ether_type = htons(ETH_P_ARP);
                    // Checks if value is copied correctly
                    short etype = ntohs(send_eth.ether_type);
                    printf("\nEther Type: %x\n", etype);
                    
                    /************************************************************
                     * Instantiate an arp header and store the necessary values
                     ***********************************************************/
                    struct ether_arp send_arp;
					printf("\nReceived an ARP request....\n");
                    
                    /* hardware type */
                    send_arp.ea_hdr.ar_hrd = htons(HW_TYPE);
                    // Checks if value is copied correctly
                    short hardtype = ntohs(send_arp.ea_hdr.ar_hrd);
                    printf("\tHardware Type: %x\n", hardtype);
                    
                    /* protocol type */
                    send_arp.ea_hdr.ar_pro = htons(ETH_P_IP);
                    // Checks if value is copied correctly
                    short protype = ntohs(send_arp.ea_hdr.ar_pro);
                    printf("\tProtocol Type: %x\n", protype);
                    
                    /* hardware length */
                    send_arp.ea_hdr.ar_hln = MAC_LENGTH;
                    // Checks if value is copied correctly
                    uint8_t hardlen = send_arp.ea_hdr.ar_hln;
                    printf("\tHardware Length: %x\n", hardlen);
                    
                    /* protocol length */
                    send_arp.ea_hdr.ar_pln = IPV4_LENGTH;
                    // Checks if value is copied correctly
                    uint8_t prolen = send_arp.ea_hdr.ar_pln;
                    printf("\tProtocol Length: %x\n", prolen);
                    
                    /* operation code √*/
                    send_arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);
                    // The second memcpy is for to check if value is copied correctly
                    short opcode = ntohs(send_arp.ea_hdr.ar_op);
                    printf("\tOperation Code: %x\n", opcode);
                    
                    /* source mac √*/
                    memcpy(&send_arp.arp_sha, &pairs[forwardingSocket].mac,
                           MAC_LENGTH);
                    // Checks if value is copied correctly
                    print = ether_ntoa((struct ether_addr*) &send_arp.arp_sha);
                    printf("\tSource MAC: %s\n", print);
                    
                    /* source ip √*/
                    memcpy(&send_arp.arp_spa, &pairs[forwardingSocket].ip,
                           IPV4_LENGTH);
                    // Checks if value is copied correctly
                    print = inet_ntoa(*(struct in_addr*) &send_arp.arp_spa);
                    printf("\tSource IP: %s\n", print);

                    /* tartget mac √*/
                    memset(send_arp.arp_tha, 0x00, MAC_LENGTH);
					// Checks if value is copied correctly
					print = inet_ntoa(*(struct in_addr*) &send_arp.arp_tha);
                    printf("\tSource IP: %s\n", print);
                    
                    /* target ip */
                    memcpy(&send_arp.arp_tpa, &ip_hop, IPV4_LENGTH);
                    // Checks if value is copied correctly
                    print = inet_ntoa(*(struct in_addr*) &send_arp.arp_tpa);
                    printf("\tTarget IP(Next Hop): %s\n", print);
                    char arp_request[42];
                    memcpy(&arp_request[0], &send_eth, EH_LENGTH);
                    memcpy(&arp_request[14], &send_arp, EH_LENGTH+IP_H_LEN);
                    send(pairs[forwardingSocket].packetSocket, arp_request, 42,
                         0);
                    printf("\n-----------Arp Requested!-----------\n");
                }
                
                /************************************************************
                 * Forward the IP packet if the arp request succeed
                 ***********************************************************/
                if (arptype == ARPOP_REPLY) {
                    /* Store etherheader of current arp reply */
                    struct ether_header *arp_reply_eh =
                    (struct ether_header*) buf;
                    /* Store etherheader of forwarding packet */
                    struct ether_header *forward_eh =
                    (struct ether_header*) forward_buf;
                    
                    arpRequested = 1;
                    /* Modify etherheader of forwarding packet */
                    memcpy(&forward_eh->ether_dhost, &arp_reply_eh->ether_shost,MAC_LENGTH);
                    memcpy(&forward_eh->ether_shost, &arp_reply_eh->ether_dhost,MAC_LENGTH);
                    /* Store the arp mac for later use */
                    char *printi;
                    printi = ether_ntoa((struct ether_addr*) &forward_eh->ether_shost);
                    printf("Forwarding IP Packet Source MAC: %s\n", printi);
                    printi = ether_ntoa((struct ether_addr*) &forward_eh->ether_dhost);
                    printf("Forwarding IP Packet Destination MAC: %s\n", printi);
                    struct ether_header *eh = (struct ether_header*) forward_buf;
                    struct iphdr *ip_now = (struct iphdr*) (forward_buf
                                                            + EH_LENGTH);
                    send(pairs[currentSocket].packetSocket, forward_buf, 1500,0);
                    printf("\n----------Packet Forwarded------------\n");
                }
            }
        }
    }
    //free the interface list when we don't need it anymore
    freeifaddrs(ifaddr);
    //exit
    return 0;
}

/************************************************************
 * CHECK SUM FUNCTION
 ***********************************************************/
// From
//u_short chsum(u_short *buf, int count) {
unsigned short chsum(unsigned short *buf, int count) {
    //register u_long sum = 0;
    register unsigned long sum = 0;
    while (count--) {
        sum += *buf++;
        if (sum & 0xFFFF0000) {
            // carry occurred - so, wrap around!
            sum &= 0xFFFF;
            sum++;
        }
    }
    return ~(sum & 0xFFFF);
}

unsigned short myChecksum(unsigned char *packet, int length) {
	register unsigned long sum = 0;
	int i;
	for (i = 0; i < length; i++) {
		sum += *packet++;
		if (sum & 0xFFFF0000) {
			sum &= 0xFFFF;	// keep lowest 2 bytes, 16 bits
			sum++;
		}	
	}
	return ~(sum & 0xFFFF);
}




