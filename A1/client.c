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
    perform_http(sockid,identifier);

    //printf("%s\n", hostname);
    //printf("%s\n", identifier);
    //printf("%d\n", port);


}

/*------ Parse an "uri" into "hostname" and resource "identifier" --------*/

parse_URI(char *uri, char *hostname, int *port, char *identifier)
{

  if (strstr(uri,"http") == NULL && strstr(uri,"HTTP") == NULL){
    perror("Not Valid URI\n");
    exit(1);
  }

  if (strstr(uri,":") != NULL ){
  sscanf(uri,"http://%[^:|/\n]:%d/%[^\n]",hostname,port,identifier);
  } else {
  scanf(uri,"http://%[^/]/%99s[^\n]",hostname,identifier);
  }
  printf("%s\n", hostname);
  printf("%d\n",*port );
  printf("%s\n", identifier);



/*
  char * i;
  int double_slash = 0;
  for (i=uri; *i; i++){
    if (*i == '/'){
      double_slash++;
    }
    if (double_slash == 2){
      i++;
      double_slash = 0;
      while (1){

        if(*i == '/' || *i == ':'){

          break;
        }
        //printf("%s\n", i);
        i++;

      }
    }
  }
  */


}

/*------------------------------------*
* connect to a HTTP server using hostname and port,%s
* and get the resource specified by identifier
*--------------------------------------*/
perform_http(int sockid, char *identifier)
{


  char buffer[MAX_RES_LEN];
  char message[200];
  strcpy(message, "GET ");
  strcat(message, " /index.htm");
  strcat(message, " HTTP/1.0\r\n\r\n");
  //printf("%s\n", message );

  //char * message = "GET http://www.csc.uvic.ca/index.htm HTTP/1.0\r\n\r\n";
    if( send(sockid , message , strlen(message) , 0) < 0)
    {
        perror("Send failed\n");
        exit(1);
    }

    if( recv(sockid, buffer , MAX_RES_LEN-1 , 0) < 0)
    {
        perror("Receive failed\n");
        exit(1);
    }

    puts(buffer);
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
    perror("ERROR Opening Socket\n");
    exit(1);
  }
  struct sockaddr_in sa;
  bzero(&sa, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(9898);
  inet_pton(AF_INET,"127.0.0.1",&(sa.sin_addr));

  //printf("Before connect\n");
  connect(sockfd, (struct sockaddr *) &sa, sizeof(sa));



  return sockfd;
}
