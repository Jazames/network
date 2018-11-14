#include "frameio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

frameio net;             // gives us access to the raw network

struct ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[1500];     // payload
};

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

      octet* this_is_wrong_to_do = (octet*) &buf;
      for(int i = 0; i < 42; i++)
      {
        printf("%02x ", this_is_wrong_to_do[i]);
        if(i == 21 || i == 41)
        {
          printf("\n");          
        }
      }

      switch ( buf.prot[0]<<8 | buf.prot[1] )
      {
          case 0x800:
             printf("Found IP frame from ip: %d.%d.%d.%d \n\n",buf.data[12],buf.data[13],buf.data[14],buf.data[15]);
             break;
           case 0x806:
             printf("Received an ARP frame.\n");
             break;
      }
      printf("\n\n");
   }
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
  printf("Socket: %d\n", socket); 
 
  pthread_create(&loop_thread,NULL,protocol_loop,NULL);
  for ( ; ; )
    sleep(1);
}

