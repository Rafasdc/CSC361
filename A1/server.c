#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*------------------------------
* server.c
* Description: HTTP server program
* CSC 361
* Instructor: Kui Wu
-------------------------------*/


#define MAX_STR_LEN 120         /* maximum string length */
#define SERVER_PORT_ID 9898     /* server port number */

void cleanExit();

/*---------------------main() routine--------------------------*
 * tasks for main
 * generate socket and get socket id,
 * max number of connection is 3 (maximum length the queue of pending connections may grow to)
 * Accept request from client and generate new socket
 * Communicate with client and close new socket after done
 *---------------------------------------------------------------------------*/

main(int argc, char *argv)
{
    int newsockid; /* return value of the accept() call */
    int port,sockfd,newsockfd;
    struct sockaddr_in serv_addr,cli_addr;
    while (1)
    {
      close(newsockid);
    }
}

/*---------------------------------------------------------------------------*
 *
 * cleans up opened sockets when killed by a signal.
 *
 *---------------------------------------------------------------------------*/

void cleanExit()
{
    exit(0);
}

/*---------------------------------------------------------------------------*
 *
 * Accepts a request from "sockid" and sends a response to "sockid".
 *
 *---------------------------------------------------------------------------*/

perform_http(int sockid)
{

}
