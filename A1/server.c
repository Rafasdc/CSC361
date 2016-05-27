#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/*------------------------------
* server.c
* Description: HTTP server program
* CSC 361
* Instructor: Kui Wu
* Student: Rafael Solorzano
* V00838235
-------------------------------*/


#define MAX_STR_LEN 120         /* maximum string length */
#define SERVER_PORT_ID 9898     /* server port number */

void cleanExit(int);

/*---------------------main() routine--------------------------*
 * tasks for main
 * generate socket and get socket id,
 * max number of connection is 3 (maximum length the queue of pending connections may grow to)
 * Accept request from client and generate new socket
 * Communicate with client and close new socket after done
 *---------------------------------------------------------------------------*/

main(int argc, char *argv[])
{
    int newsockid; /* return value of the accept() call */
    int port,sockfd,newsockfd;
    struct sockaddr_in serv_addr,cli_addr;
    char * directory;


/*
    if (argc < 2){
      printf("Usage:\n ./simpServer portnumber directoryofHTML\n or \n ./simpServer directoryofHTML (defaults to port 80)\n");
      exit(1);
    }

    if (argc == 3){
      port = atoi(argv[1]);
      directory = argv[2];
    } else if (argc == 2){
      directory = argv[1];
      port = 80;
    }
    printf("Directory:%s and Port:%d\n", directory,port);


    exit(1);
    */

    port = SERVER_PORT_ID;

    sockfd = socket(AF_INET,SOCK_STREAM,0);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sockfd,(struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
      perror("ERROR on binding");
      exit(1);
    }

    if (listen(sockfd,3) < 0){
      perror("ERROR on listen");
      exit(1);
    }
    char buffer[256];

    //Handle CTRL-C when server quit to close socket
    //prevents error of Address in use
    signal(SIGINT, cleanExit);

    //Inifnite loop to get request from client
    while (1)
    {
      newsockid = accept(sockfd, (struct sockaddr*)NULL,NULL);
      perform_http(newsockid);
      close(newsockid);
    }
}

/*---------------------------------------------------------------------------*
 *
 * cleans up opened sockets when killed by a signal.
 *
 *---------------------------------------------------------------------------*/

void cleanExit(int sig)
{
    signal(sig,SIG_IGN);
    printf("\nServer Closing... Cleaning\n");
    exit(0);
}

/*---------------------------------------------------------------------------*
 *
 * Accepts a request from "sockid" and sends a response to "sockid".
 *
 *---------------------------------------------------------------------------*/

perform_http(int sockid)
{
  //status codes to send response
  char * not_implemented = "HTTP/1.0 501 Not Implemented\nServer: Linux\n";
  char * status_ok = "HTTP/1.0 200 OK\nServer: Linux\n";
  char * not_found = "HTTP/1.0 404 Not Found\nServer: Linux\n";

  int n = 0; //used for error checking

  //buffer to get message sent by client
  char buffer[MAX_STR_LEN];
  n = read(sockid,buffer,255);

  if (n < 0){
    perror("ERROR on read");
    exit(1);
  }

  printf("Got a request!\n");

  //parses request of client into method, identifier, and protocol
  char method[MAX_STR_LEN];
  char identifier[MAX_STR_LEN];
  char protocol[MAX_STR_LEN];
  sscanf(buffer,"%s %s %s",method,identifier,protocol);
  printf("%s %s %s\n", method, identifier, protocol);

  //check if method is get and correct http protocol
  if (strstr(method,"GET") == NULL || strstr(protocol,"HTTP/1.0") == NULL){
    n = writen(sockid, not_implemented, MAX_STR_LEN);
    if (n < 0){
      perror("ERROR on write");
      exit(1);
    }
  // if GET method and HTTP 1.0 then we get file requested
  } else {
    char file[MAX_STR_LEN];
    sprintf(file,".%s",identifier);
    printf("%s\n", file);
    FILE *fp;
    fp = fopen(file,"r");
    if (fp == NULL){
      //if the file does not exist then we seng 404 error
      n = writen(sockid,not_found,MAX_STR_LEN);
    } else {
      //the file was opened succesfully so get the html data
      char html_file[250];
      int i = 0;
      int c;
      //copies the file into a char
      while((c = getc(fp)) != EOF){
        html_file[i] = c;
        i++;
      }
      close(fp); //close fd to prevent memory leaks
      html_file[i] = '\0'; //c style string needs null termination
      //printf("%s\n", html_file); //debug line
      //send status_ok
      n = writen(sockid, status_ok, strlen(status_ok));
      if (n < 0 ){
        perror("Error on Write");
        exit(1);
      }
      //send html file
      n = writen(sockid,html_file,strlen(html_file));
      if (n < 0 ){
        perror("Error on Write");
        exit(1);
      }

    }
  }


}
