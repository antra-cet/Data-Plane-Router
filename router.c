#include "./include/queue.h"
#include "./include/skel.h"

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *arp_table;
int arp_table_len;


struct route_table_entry *best_route(uint32_t destination_ip)
{
	size_t idx = -1;
	size_t l = 0, r = rtable_len - 1;

	while (l <= r) {
		size_t m = (r + l) / 2;
		if ((destination_ip & rtable[m].mask) == rtable[m].prefix) {
			if (idx == -1) {
				idx = m;
			} else {
				if (ntohl(rtable[idx].mask) < ntohl(rtable[m].mask)) {
					idx = m;
				} else {
					if ((rtable[idx].mask == rtable[m].mask) &&
						(rtable[idx].next_hop > rtable[m].next_hop)) {
						idx = m;
					}
				}
			}

			l = m + 1;
		} else {
			if ((destination_ip & rtable[m].mask) < rtable[m].prefix) {
				r = m - 1;
			} else {
				l = m + 1;
			}
		}
	}
	
	// for (size_t i = 0; i < rtable_len; i++) {
	// 	if ((destination_ip & rtable[i].mask) == rtable[i].prefix) {
	// 		if (idx == -1) {
	// 			idx = i; 
	// 		} else {
	// 			if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) {
	// 				idx = i;
	// 			} else {
	// 				if ((rtable[idx].mask == rtable[i].mask) &&
	// 					(rtable[idx].next_hop > rtable[i].next_hop)) {
	// 					idx = i;
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	return ((idx == -1) ? NULL : &rtable[idx]);
}

/*
 Returns a pointer (eg. &arp_table[i]) to the best matching arpghbor table entry.
 for the given protocol and destination address. Or NULL if there is no matching route.
*/
struct arp_entry *get_arp_entry(uint32_t dest_ip) {
	for (size_t i = 0; i < arp_table_len; i++)
	{
		if (dest_ip == arp_table[i].ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}

// Used the last years's function from the skel
struct icmphdr *parse_icmp(void *buffer)
{
	struct ether_header *eth_hdr;
	struct iphdr *ip_hdr;

	eth_hdr = (struct ether_header *)buffer;
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
	{
		ip_hdr = (struct iphdr *)(buffer + sizeof(struct ether_header));
		if (ip_hdr->protocol == 1)
		{
			struct icmphdr *icmp_hdr;
			icmp_hdr = (struct icmphdr *)(buffer + sizeof(struct iphdr) + sizeof(struct ether_header));
			return icmp_hdr;
		}
		else
			return NULL;
	}
	else
		return NULL;
}

void build_ethhdr(struct ether_header *eth_hdr, uint8_t *sha, uint8_t *dha, unsigned short type)
{
	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	eth_hdr->ether_type = type;
}

void send_icmp(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq)
{

	struct ether_header eth_hdr;
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
		.un.echo = {
			.id = id,
			.sequence = seq,
		}};
	packet packet;
	void *payload;

	build_ethhdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	/* No options */
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum(&ip_hdr, sizeof(struct iphdr));

	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	packet.interface = interface;
	send_packet(&packet);
}

void send_icmp_error(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface)
{

	struct ether_header eth_hdr;
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
	};
	packet packet;
	void *payload;

	build_ethhdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	/* No options */
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum(&ip_hdr, sizeof(struct iphdr));

	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	packet.interface = interface;
	send_packet(&packet);
}

int compare_rtable(const void *rt1, const void* rt2) {
	// uint32_t min_mask = ((struct route_table_entry *) rt1)->mask;
	// if (((struct route_table_entry *)rt2)->mask < min_mask) {
	// 	min_mask = ((struct route_table_entry *)rt2)->mask;
	// }

	uint32_t p1 = ((struct route_table_entry *)rt1)->prefix;
	uint32_t p2 = ((struct route_table_entry *)rt2)->prefix;

	uint32_t m1 = ((struct route_table_entry *)rt2)->mask;
	uint32_t m2 = ((struct route_table_entry *)rt2)->mask;

	if (m1 != m2) {
		return (ntohl(m1) - ntohl(m2));
	} else {
		return (ntohl(p1) - ntohl(p2));
	}
}

void bonus_checksum(struct iphdr *ip_hdr)
{
	uint16_t check = ip_hdr->check;
	uint16_t value = (ip_hdr->ttl & MASK_16);
	ip_hdr->ttl--;

	uint16_t newValue = (ip_hdr->ttl & MASK_16);
	uint16_t newCheck = ~(~check + ~value + newValue) - 1;
	ip_hdr->check = newCheck;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Allocating memory for the route table
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "No space for route table!\n");

	// Allocating memory for the arp table
	arp_table = malloc(sizeof(struct arp_entry) * 100000);
	DIE(arp_table == NULL, "No space for the arp table!\n");

	// Getting the route table
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	// Sorting the rtable
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), &compare_rtable);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// Extract the ether header and the ip header
		struct ether_header *eth = (struct ether_header *)m.payload;
		struct iphdr *iph = (struct iphdr *) (m.payload + sizeof(struct ether_header));

		// Extracting the icmp header and ip header
		struct icmphdr *icmp_header = parse_icmp(m.payload);

		// If it is an ip packet
		if (ntohs(eth->ether_type) == 0x0800)
		{
			// The packet is for the router
			if (inet_addr(get_interface_ip(m.interface)) == iph->daddr) {
				if (icmp_header != NULL) {
					if (icmp_header->type == ICMP_ECHO) {
						send_icmp(iph->saddr, iph->daddr, eth->ether_dhost,
								  eth->ether_shost, ICMP_ECHOREPLY, ICMP_ECHOREPLY,
								  m.interface, icmp_header->un.echo.id,
								  icmp_header->un.echo.sequence);
						continue;
					}
					continue;
				}
				continue;
			}

			// If the sum is not equal, throw the packet
			if (ip_checksum((void *)iph, sizeof(struct iphdr)) != 0) {
				continue;
			}

			// If the time is exceeded, throw the packet
			if (iph->ttl <= 1) {
				send_icmp_error(iph->saddr, inet_addr(get_interface_ip(m.interface)),
								eth->ether_dhost, eth->ether_shost,ICMP_TIME_EXCEEDED,
								0, m.interface);
				continue;
			}

			// Using the ip daddr to get the best route for the table
			uint32_t destination_ip = iph->daddr;
			struct route_table_entry *route = best_route(destination_ip);
			if (route == NULL) {
				continue;
			}

			// Updating the ttl and checksum
			iph->ttl--;
			iph->check = 0;
			iph->check = ip_checksum((void *)iph, sizeof(struct iphdr));

			// If there is a next hop, searching for its mac address
			struct arp_entry *arp = get_arp_entry(route->next_hop);
			if (arp == NULL) {
				continue;
			}

			memcpy(eth->ether_dhost, arp->mac, 6);
			get_interface_mac(route->interface, eth->ether_shost);
			m.interface = route->interface;
			send_packet(&m);
		}
	}

	free(rtable);
	free(arp_table);
}
