#include "frameio.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "arp_util.hpp"
#include <string>
#include <exception>

frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack
message_queue arp_queue; // message queue for the ARP protocol stack


//
// This thread sits around and receives frames from the network.
// When it gets one, it dispatches it to the proper protocol stack.
//
void *protocol_loop(void *arg)
{
   ether_frame buf;
   while(1)
   {

      int n = net.recv_frame(&buf,sizeof(buf));
      if ( n < 42 ) continue; // bad frame!
      switch ( buf.prot[0]<<8 | buf.prot[1] )
      {
          case 0x800:
             ip_queue.send(PACKET,buf.data,n);
             break;
          case 0x806:
             arp_queue.send(PACKET,buf.data,n);
             break;
      }
   }
}

//
// Toy function to print something interesting when an IP frame arrives
//
void *ip_protocol_loop(void *arg)
{
   octet buf[1500];
   event_kind event;
   int timer_no = 1;

   // for fun, fire a timer each time we get a frame
   while ( 1 )
   {
      ip_queue.recv(&event, buf, sizeof(buf));
      if ( event != TIMER )
      {
         //printf("got an IP frame from %d.%d.%d.%d, queued timer %d\n",
         //         buf[12],buf[13],buf[14],buf[15],timer_no);
         ip_queue.timer(10,timer_no);
         timer_no++;
      }
      else
      {
         //printf("timer %d fired\n",*(int *)buf);
      }
   }
}




//
// Toy function to print something interesting when an ARP frame arrives
//
void *arp_protocol_loop(void *arg)
{
   octet buf[1500];
   event_kind event;

   while ( 1 )
   {
      arp_queue.recv(&event, buf, sizeof(buf));
      if(event != TIMER)
      {
        //printf("got an ARP %s\n", buf[7]==1? "request":"reply");
        handle_arp_event(net, buf, arp_queue);
      }
      else
      {
        timeout_cache_entry(*(int*)buf);
      }
   }
}


std::vector<std::string> split_string(std::string str, std::string delim)
{
    std::vector<std::string> tokens;
    size_t prev = 0, pos = 0;
    do
    {
        pos = str.find(delim, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos-prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
    }
    while (pos < str.length() && prev < str.length());
    return tokens;
}


octet* string_to_ip(std::string ip_string)
{
  static octet ip[4] = {0,0,0,0};
  std::vector<std::string> chunks = split_string(ip_string, ".");
  if(chunks.size() == 4)//Make sure there are the right number of things. 
  {
    try
    {
      ip[0] = std::stoi(chunks[0],nullptr,10);
      ip[1] = std::stoi(chunks[1],nullptr,10);
      ip[2] = std::stoi(chunks[2],nullptr,10);
      ip[3] = std::stoi(chunks[3],nullptr,10);
    }
    catch(std::exception e)
    {
      std::cout << "Error in parsing IP Address. Exception: "  << std::endl;
    }
  }
  return ip;
}

//
// if you're going to have pthreads, you'll need some thread descriptors
//
pthread_t loop_thread, arp_thread, ip_thread;

//
// start all the threads then step back and watch (actually, the timer
// thread will be started later, but that is invisible to us.)
//
int main()
{
  int socket = net.open_net("wlp3s0");
   
  std::cout << "Socket: " << socket <<  std::endl;

  pthread_create(&loop_thread,NULL,protocol_loop,NULL);
  pthread_create(&arp_thread,NULL,arp_protocol_loop,NULL);
  pthread_create(&ip_thread,NULL,ip_protocol_loop,NULL);
  for ( ; ; )
  {
    //std::string ip_string;
    //std::cin >> ip_string;
    static octet some_ip[4] = {192,168,1,1};
    static octet some_other_ip[4] = {192,168,1,102};
    //octet* ip = string_to_ip(ip_string);

    //Attempt to send an unsolicited ARP reply to a hard-coded address every 9 seconds. 
    sleep(9);

    std::cout << "Attempting to send an unsolicited ARP reply." << std::endl;
    send_some_arp_message(net, some_other_ip);
  }

  sleep(1);
}

