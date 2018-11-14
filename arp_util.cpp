#include"arp_util.hpp"


static octet my_ip[4]  = {192,168,1,105};
static octet my_mac[6] = {0x7c,0xd1,0xc3,0x95,0x99,0x20};
static octet broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
std::vector<ip_mac_pair> cached_ip_mac_pairs;



void print_ip(octet* ip)
{
  printf("%d",ip[0]);
  for(int i=1;i<4;i++)
  {
    printf(".%d",ip[i]);
  }
}

void print_mac(octet* mac)
{
  printf("%02x",mac[0]);
  for(int i=1;i<6;i++)
  {
    printf(":%02x", mac[i]);
  }
}

//Returns true if removed. 
bool timeout_cache_entry(int position)
{
  //Check to see if a pair needs to be evicted from the cache. 
  cached_ip_mac_pairs[position].cache_count--;
  //std::cout << "Decrementing at postion " << position << std::endl;
  if(cached_ip_mac_pairs[position].cache_count <= 0)
  {
    cached_ip_mac_pairs.erase(cached_ip_mac_pairs.begin() + position);
    std::cout << "Removing cache entry at position " << position << std::endl;
    return true;
  }
  return false;
}


void handle_arp_event(frameio& net_access, octet * data, message_queue& arp_queue)
{
  if(data[7] == 1)//Got a request.
  {
    //If ip matches, send a reply. 
    if(are_ips_equal(my_ip, data+24))
    {
      std::cout << "Sending an ARP Reply" << std::endl;
      send_arp_reply(net_access, my_mac, my_ip, data+8, data+14);
    }
  }
  else if(data[7] == 2)//Got a reply, better cache me out back, how bout dat?
  {
    //Cache the target
    cache_pair(data+24, data+18, arp_queue);
  }
  //Regardless of what kind it is, cache the sender.
  cache_pair(data+14, data+8, arp_queue);
}



bool are_ips_equal(octet* a, octet* b)
{
  //find out if IP matches
    for(int i=0;i<4;i++)
    {
      if(a[i] != b[i])
      {
        return false;
      }
    }
    return true;
}

bool are_macs_equal(octet* a, octet* b)
{
  //find out if IP matches
    for(int i=0;i<6;i++)
    {
      if(a[i] != b[i])
      {
        return false;
      }
    }
    return true;
}


void send_some_arp_message(frameio& net_access, octet* ip)
{
  get_mac_in_cache(net_access, ip);
  //Spin and wait for the 
  while(get_mac_position_in_cache(ip) < 0)
  {
    static auto start_time = std::chrono::system_clock::now();
    auto current_time = std::chrono::system_clock::now();
    if(current_time > start_time + std::chrono::seconds(5))//If it's been more than five seconds, give up. 
    {
      std::cout << "Mac Address for IP: ";
      print_ip(ip);
      std::cout <<  " cannot be obtained." << std::endl;
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  octet* mac = get_mac_from_cache(ip);

  //Send an arp reply. 
  std::cout << "Sending unsolicted ARP reply to ";
  print_ip(ip);
  std::cout << std::endl;
  send_arp_reply(net_access, my_mac, my_ip, mac, ip);
}

//
void get_mac_in_cache(frameio& net_access, octet* ip)
{
  octet* mac = get_mac_from_cache(ip);
  if(are_macs_equal(mac, broadcast_mac))//If not a mac address, then need to get it. 
  {
    send_arp_request(net_access, my_mac, my_ip, ip);
    std::cout << "MAC address not found in cache, sending request to obtain it." << std::endl;
    return;
  }
  std::cout << "MAC address found in cache." << std::endl;
}

octet* get_mac_from_cache(octet* ip)
{
  for(uint i=0; i<cached_ip_mac_pairs.size(); i++)
  {
    if(are_ips_equal(ip, (octet*)&(cached_ip_mac_pairs[i].ip)))
    {
      return (octet*)&(cached_ip_mac_pairs[i].mac);
    }
  }
  return (octet*)&broadcast_mac;
}

int get_mac_position_in_cache(octet* ip)
{
  for(uint i=0; i<cached_ip_mac_pairs.size(); i++)
  {
    if(are_ips_equal(ip, (octet*)&(cached_ip_mac_pairs[i].ip)))
    {
      return i;
    }
  }
  return -1;
}

void cache_pair(octet* ip, octet* mac, message_queue& arp_queue)
{
  octet* temp_mac = get_mac_from_cache(ip);
  if(are_macs_equal(temp_mac, mac))
  {
    int pos = get_mac_position_in_cache(ip);
    cached_ip_mac_pairs[pos].cache_count++;
    //std::cout << "Got a pair already in the cache at position " << pos << " with count " << cached_ip_mac_pairs[pos].cache_count << std::endl;
  }
  else
  {
    std::cout << "Cacheing pair:"<< std::endl;
    print_ip(ip);
    std::cout << " at ";
    print_mac(mac);
    std::cout << std::endl;
    std::cout << "At position " << cached_ip_mac_pairs.size() << " in the cache." << std::endl;
    ip_mac_pair pair;
    for(int i=0;i<6;i++)
    {
      pair.mac[i] = mac[i];
    }
    for(int i=0;i<4;i++)
    {
      pair.ip[i] = ip[i];
    }
    pair.cache_count = 1;
    cached_ip_mac_pairs.push_back(pair);
    int pos = cached_ip_mac_pairs.size() - 1;//Will get the position of the last element. 
    //Set 20 second expiry timer for the cache. 
    arp_queue.timer(200, pos);
  }
}

void send_arp_request(frameio& net_access, octet* source_mac, octet* sender_ip, octet* target_ip)
{
  static ether_frame frame;
  int data_size = 28; //Might need to add 18 bytes to pad, also might need to add ethernet frame footer stuff? 
  int padding_size = 18;
  int length = 6 + 6 + 2 + data_size + padding_size;

  //Fill in areas that take mac addresses
  for(int i = 0; i < 6; i++)
  {
    frame.dst_mac[i] = 0xFF;
    frame.src_mac[i] = source_mac[i];
    frame.data[8 + i] = source_mac[i]; //sender mac
    frame.data[18 + i] = 0x00; //target mac
  }
  //Frame protocol = 0x0806 for ARP
  frame.prot[0] = 0x08;
  frame.prot[1] = 0x06;

  //Set up ARP reply information.
  //Hardware Type = 0x0001
  frame.data[0] = 0x00;
  frame.data[1] = 0x01;
  //Protocol Type = 0x0800
  frame.data[2] = 0x08;
  frame.data[3] = 0x00;
  //Hardware Address Length = 6
  frame.data[4] = 6;
  //Protocol Address Length = 4
  frame.data[5] = 4;
  //Opcode = 1 for request, 2 for reply
  frame.data[6] = 0x00;
  frame.data[7] = 0x01;
  //Sender's hardware Address
    //frame.data[8-13] = mac address
  //Sender's IP address
    //frame.data[14-17] = ip address

  //Put in ip addresses. 
  for(int i=0; i<4; i++)
  {
    frame.data[14 + i] = sender_ip[i]; 
    frame.data[24 + i] = target_ip[i]; 
  }
  //Target's Hardware Address
    //frame.data[18-23] = mac address
  //Target's IP Address
    //frame.data[24-27] = ip address
  //Padding, 18 bytes. 

  //Put in padding
  for(int i=0;i<padding_size;i++)
  {
    frame.data[28 + i] = 0x00;
  }
  net_access.send_frame(&frame, length);
}


void send_arp_reply(frameio& net_access, octet* source_mac, octet* sender_ip, octet* destination_mac, octet* target_ip)
{
  ether_frame frame;
  int data_size = 28; //Might need to add 18 bytes to pad, also might need to add ethernet frame footer stuff? 
  int padding_size = 18;
  int length = 6 + 6 + 2 + data_size + padding_size;

  //Fill in areas that take mac addresses
  for(int i = 0; i < 6; i++)
  {
    frame.dst_mac[i] = destination_mac[i];
    frame.src_mac[i] = source_mac[i];
    frame.data[8 + i] = source_mac[i]; //sender mac
    frame.data[18 + i] = destination_mac[i]; //target mac
  }
  //Frame protocol = 0x0806 for ARP
  frame.prot[0] = 0x08;
  frame.prot[1] = 0x06;

  //Set up ARP reply information.
  //Hardware Type = 0x0001
  frame.data[0] = 0x00;
  frame.data[1] = 0x01;
  //Protocol Type = 0x0800
  frame.data[2] = 0x08;
  frame.data[3] = 0x00;
  //Hardware Address Length = 6
  frame.data[4] = 6;
  //Protocol Address Length = 4
  frame.data[5] = 4;
  //Opcode = 1 for request, 2 for reply
  frame.data[6] = 0x00;
  frame.data[7] = 0x02;
  //Sender's hardware Address
    //frame.data[8-13] = mac address
  //Sender's IP address
    //frame.data[14-17] = ip address

  //Put in ip addresses. 
  for(int i=0; i<4; i++)
  {
    frame.data[14 + i] = sender_ip[i]; 
    frame.data[24 + i] = target_ip[i]; 
  }
  //Target's Hardware Address
    //frame.data[18-23] = mac address
  //Target's IP Address
    //frame.data[24-27] = ip address
  //Padding, 18 bytes. 

  //Put in padding
  for(int i=0;i<padding_size;i++)
  {
    frame.data[28 + i] = 0x00;
  }
  //*
  printf("Sending ARP Reply with payload: \n");
  for(int i=0;i<length;i++)
  {
    printf("0x%02x, ",frame.data[i]);
    if(i%8 == 0)
      printf("  ");
    if(i%16 == 0)
      printf("\n");
  }
  printf("\n");
  //*/
  net_access.send_frame(&frame, length);
}

