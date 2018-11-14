#ifndef ARP_UTIL_HPP
#define ARP_UTIL_HPP



#include<thread>
#include<chrono>
#include<iostream>
#include"frameio.h"
#include<vector>
#include"util.h"

struct ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[1500];     // payload
};


struct ip_mac_pair
{
  octet ip[4];
  octet mac[6];
  int cache_count = 0;
};

void handle_arp_event(frameio& net_access, octet* data, message_queue& arp_queue);
void send_arp_request(frameio& net_access, octet* source_mac, octet* sender_ip, octet* target_ip);
void send_arp_reply(frameio& net_access, octet* source_mac, octet* sender_ip, octet* destination_mac, octet* target_ip);
bool are_ips_equal(octet* a, octet* b);
bool are_macs_equal(octet* a, octet* b);
void send_some_arp_message(frameio& net_access, octet* ip);
void get_mac_in_cache(frameio& net_access, octet* ip);
octet* get_mac_from_cache(octet* ip);
int get_mac_position_in_cache(octet* ip);
void cache_pair(octet* ip, octet* mac, message_queue& arp_queue);
bool timeout_cache_entry(int position);
void print_ip(octet* ip);
void print_mac(octet* mac);

#endif //ARP_UTIL_HPP