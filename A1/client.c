#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*------------------------------
* client.c
* Description: HTTP client program
* CSC 361
* Instructor: Kui Wu
* Student: Rafael Solorzano
* V00838235
-------------------------------*/

/* define maximal string and reply length, this is just an example.*/
/* MAX_RES_LEN should be defined larger (e.g. 4096) in real testing. */
#define MAX_STR_LEN 120
#define MAX_RES_LEN 4096

/* --------- Main() routine ------------
 * three main task will be excuted:
 * accept the input URI and parse it into fragments for further operation
 * open socket connection with specified sockid ID
 * use the socket id to connect sopecified server
 * don't forget to handle errors
 */

main(int argc, char **argv)
{
    char uri[MAX_STR_LEN];
    char hostname[MAX_STR_LEN];
    char identifier[MAX_STR_LEN];
    int sockid, port;
    port = 80;

    printf("Open URI:  ");
    scanf("%s", uri);

    parse_URI(uri,hostname,&port,identifier);
    sockid = open_connection(hostname,port);
    perform_http(sockid,identifier,uri,hostname);


}

/*------ Parse an "uri" into "hostname" and resource "identifier" --------*/

parse_URI(char *uri, char *hostname, int *port, char *identifier)
{

  //If user does not provde http:// the program will fail
  if (strstr(uri,"http") == NULL){
    printf("Not Valid URI\n");
    exit(1);
  }

  //Parses uri into hostname port and identifier
  //first if tries to find port number if not succesfull then second parse
  //is executed
  if (sscanf(uri,"http://%[^:|/\n]:%d%[^\n]",hostname,port,identifier) != 3){
    sscanf(uri,"http://%[^/\n]%[^\n]",hostname,identifier);
  }
  //printf("%s\n", hostname);
  //printf("%d\n",*port );
  //printf("%s\n", identifier);

}

/*------------------------------------*
* connect to a HTTP server using hostname and port,%s
* and get the resource specified by identifier
*--------------------------------------*/
perform_http(int sockid, char *identifier, char *uri, char * hostname)
{
  //Chars to store buffer of received content, header, body and message to send
  char buffer[MAX_RES_LEN];
  char rheader[MAX_RES_LEN];
  char body [MAX_RES_LEN];
  char message[200];
  /*
  *  Creating message to send
  *  Change GET to POST or HTTP/1.0 to HTTP/1.1 to get
  *  501 Not implemented response from simpServer
  */
  sprintf(message,"GET %s HTTP/1.0\r\n\r\n",identifier);
  //Assignment requred format
  printf("---Request Begin---\n");
  printf("Host: %s\n", hostname );
  printf("%s", message );

    if( send(sockid , message , strlen(message) , 0) < 0)
    {
        perror("Send failed\n");
        exit(1);
    }
    //Assignment required format
    //Send done succesfully
    printf("---Request end---\nHTTP request sent, awaiting response...\n\n");

    if( recv(sockid, buffer , MAX_RES_LEN-1 , 0) < 0)
    {
        perror("Receive failed\n");
        exit(1);
    }
    //Receie succesfull
    printf("---Response header---\n");
    //Scan Header until HTML file begginer found
    sscanf(buffer,"%[^<]",rheader);
    //print the header
    puts (rheader);
    //start body
    printf("---Response body---\n");
    //method to find the first < of HTML file
    //if not found there was no body respond
    char *e;
    int index;
    e = strchr(buffer,'<');
    if (e == NULL){
      //no body
    } else {
      index = (int)(e-buffer);
      strncpy(body,buffer+index,MAX_RES_LEN);
      puts(body);
    }
    close(sockid);
}

/*---------------------------------------------------------------------------*
 *
 * open_conn() routine. It connects to a remote server on a specified port.
 *
 *---------------------------------------------------------------------------*/

int open_connection(char *hostname, int port)
{

  int sockfd;
  /* generate socket
   * connect socket to the host address
   */
  sockfd = socket(AF_INET,SOCK_STREAM,0);
  if (sockfd < 0){
    perror("ERROR Opening Socket");
    exit(1);
  }

  //conversta char host to compatible sa.sin_addr
  struct hostent *hp = gethostbyname(hostname);

  struct sockaddr_in sa;
  bzero(&sa, sizeof sa);
  memcpy(&sa.sin_addr,hp->h_addr,hp->h_length);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);


  //printf("Before connect\n");
  //Connects to server
  if (connect(sockfd, (struct sockaddr *) &sa, sizeof(sa))){
    perror("Connect Failed");
    exit(1);
  }

  return sockfd;
}
