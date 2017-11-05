#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
/*
 * pbproxy [-l port] -k keyfile destination port
 */


#define MAX_BUFFER_SIZE 1024

void print_app_usage()
{
   printf("Usage:\n");
   printf("  pbproxy [-l port] -k keyfile destination port\n");
}

int is_number(char* str)
{
    while (*str)
    {
       if (*str < '0' || *str > '9')
          return 0;
       str++;
    }

    return 1;
}


void exit_err(char* str)
{
   char pstr[MAX_BUFFER_SIZE] = "";
   strcat(pstr, "error: ");
   strcat(pstr, str);
   strcat(pstr, "\n\n");
   fprintf(stderr, "%s", pstr);
   print_app_usage();
   exit(EXIT_FAILURE);
  
}

void exit_perr(char* str)
{
   perror(str);
   exit(EXIT_FAILURE);
}

int max(int a, int b)
{
   return ((a > b) ? a : b);
}

int main(int argc, char **argv)
{

   int   lport = -1;
   int   dport = -1;
   char* destaddr = NULL;
   char* keyfile = NULL;
   int   opt;
   int   client = 1;
   char* temp;
   char  buffer[MAX_BUFFER_SIZE+1] = {0};

   while ((opt = getopt(argc, argv, "l:k:")) != -1){
      switch (opt){
         case 'l':
            temp = optarg;
            if (!is_number(temp))
               exit_err("Invalid input for port number");
            lport = atoi(temp);
            break;
         case 'k':
            keyfile = optarg;
            break;
         default:
            exit_err("unrecognized command-line options");
            
      }
   }

   if (optind < argc)
   {
      destaddr = argv[optind];
   }
   else
   {
      exit_err("One or more mandatory parameters missing");
   }

   if (optind + 1 < argc)
   {
      temp = argv[optind+1];
      if (!is_number(temp))
         exit_err("Invalid input for port number");
      dport = atoi(temp);
   }
   else
   {
      exit_err("One or more mandatory parameters missing");
   }

   if (lport != -1)
      client = 0;

   if (!keyfile)
   {
      exit_err("keyfile is mandatory");
   }

   if (!destaddr)
   {
      exit_err("Destination IP is mandatory");
   }

   if (dport == -1)
   {
      exit_err("destination_port is mandatory");
   }

   printf("keyfile - %s, destip = %s, lport = %d, dport = %d\n", keyfile, destaddr, lport, dport);

   if (client)
   {
      int sock;
      int bytes;
      struct sockaddr_in server_addr ; 
      fd_set dset;

      if ( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      {
         exit_perr("Unable to create socket");
      }
   
      memset(&server_addr, '0', sizeof(server_addr));
   
      server_addr.sin_family = AF_INET;
      server_addr.sin_addr.s_addr = inet_addr(destaddr);
      server_addr.sin_port = htons(dport);
   
      //printf("addr - %x\n", server_addr.sin_addr.s_addr);
   //   if (inet_pton(AF_INET, destaddr, &server_addr.sin_addr) <=0)
   //      exit_perr("Invalid address");
   
      if (connect(sock, (const struct sockaddr*)&server_addr, sizeof(server_addr)))
         exit_perr("Connection failed");
   
      char* hello = "Hello from client";
   
      fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
      fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
      while (1){
         FD_ZERO(&dset);
         FD_SET(STDIN_FILENO, &dset);
         FD_SET(sock, &dset);
         select(sock+1, &dset, NULL, NULL, NULL);
   
         if (FD_ISSET(sock, &dset))
         {
            //strcpy(buffer, "Selecting 1\n");
            //write(STDOUT_FILENO, buffer, strlen(buffer));
            while(1)
            {
               bytes = read(sock, buffer, MAX_BUFFER_SIZE);
               if (bytes > 0)
               {
                  /*FILE* fp = fopen("/tmp/a", "a"); 
                  fprintf(fp,"bytes - %d\n", bytes);
                  fprintf(fp,"%s\n", buffer);
                  fclose(fp);*/
                  write(STDOUT_FILENO, buffer, bytes);
               }
               if (bytes < MAX_BUFFER_SIZE)
               {
                  //strcpy(buffer, "Breaking 1\n");
                  //write(STDOUT_FILENO, buffer, strlen(buffer));
                  //printf("Breaking 1\n");
                  break;
               }
            }
            //printf("%c\n", buffer[0]);
         }
   
         if (FD_ISSET(STDIN_FILENO, &dset))
         {
            //strcpy(buffer, "Selecting 2\n");
            //write(STDOUT_FILENO, buffer, strlen(buffer));
            while(1)
            {
               bytes = read(STDIN_FILENO, buffer, MAX_BUFFER_SIZE);
               if (bytes > 0)
               { 
                  /*FILE* fp = fopen("/tmp/b", "a"); 
                  fprintf(fp,"bytes - %d\n", bytes);
                  fprintf(fp,"%s\n", buffer);
                  fclose(fp);
                  */
                  //write(STDOUT_FILENO, buffer, bytes);
                  write(sock, buffer, bytes);
               }
               if (bytes < MAX_BUFFER_SIZE)
               {
                  strcpy(buffer, "Breaking 2\n");
                  //write(STDOUT_FILENO, buffer, strlen(buffer));
                  //printf("Breaking 2\n");
                  break;
               }
            }
         }
         /*
         else
         {
            strcpy(buffer,"Something bad happend\n");
            write(STDOUT_FILENO, buffer, strlen(buffer));
         }*/
      }
      close(sock);
   }
   else
   {
      int new_sock, sock, opt = 1;
      int len;
      int bytes;
      struct sockaddr_in server_addr ; 
      fd_set dset;
      if ( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      {
         exit_perr("Unable to create socket");
      }
   
      if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                      &opt, sizeof(opt)))
         exit_perr("setsockopt failure");
   
      memset(&server_addr, '0', sizeof(server_addr));
   
      server_addr.sin_family = AF_INET;
      server_addr.sin_addr.s_addr = INADDR_ANY;
      server_addr.sin_port = htons(lport);
   
      if (bind(sock, (const struct sockaddr*)&server_addr, sizeof(server_addr)))
         exit_perr("Bind failed");
   
      if (listen(sock, 1) < 0)
         exit_perr("Listen failed");
   
      while(1){
   
         if ((new_sock = accept(sock, (struct sockaddr*)&server_addr,
                                (socklen_t*)&len)) <0)
            exit_perr("accept failed");
   
         printf("\n\n\nNew client \n");
         int ps_sock; // proxy server sock
         struct sockaddr_in ps_server_addr ; 
         if ( (ps_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
         {
            exit_perr("Unable to create pssocket");
         }
   
         memset(&ps_server_addr, '0', sizeof(ps_server_addr));
   
         ps_server_addr.sin_family = AF_INET;
         ps_server_addr.sin_addr.s_addr = inet_addr(destaddr);
         ps_server_addr.sin_port = htons(dport);
   
   //      if (inet_pton(AF_INET, destaddr, &ps_server_addr.sin_addr) <=0)
   //         exit_perr("Invalid address");
   
         if (connect(ps_sock, (const struct sockaddr*)&ps_server_addr, sizeof(ps_server_addr)))
            exit_perr("Connection failed");
   
         fcntl(ps_sock, F_SETFL, fcntl(ps_sock, F_GETFL) | O_NONBLOCK);
         fcntl(new_sock, F_SETFL, fcntl(new_sock, F_GETFL) | O_NONBLOCK);
         while (1){
            FD_ZERO(&dset);
            FD_SET(ps_sock, &dset);
            FD_SET(new_sock, &dset);
   
            select(max(ps_sock, new_sock)+1, &dset, NULL, NULL, NULL);
   
            if (FD_ISSET(ps_sock, &dset))
            {
               while(1)
               {
                  bytes = read(ps_sock, buffer, MAX_BUFFER_SIZE);
                  if (bytes > 0)
                  {
                     send(new_sock, buffer, bytes, 0);
                     buffer[bytes] = 0;
                     printf("bytes = %d, Right -> Left : %s\n", bytes, buffer);
                  }
                  if (bytes < MAX_BUFFER_SIZE)
                     break;
               }
            }
   
            if (FD_ISSET(new_sock, &dset))
            {
               while(1)
               {
                  bytes = read(new_sock, buffer, MAX_BUFFER_SIZE);
                  if (bytes > 0)
                  {
                     send(ps_sock, buffer, bytes, 0);
                     buffer[bytes] = 0;
                     printf("bytes = %d, Left -> Right : %s\n", bytes, buffer);
                  }
                  if (bytes < MAX_BUFFER_SIZE)
                     break;
               }
            }
         }
   
   /* 
         printf("\n\n\nNew client \n");
         char buffer[MAX_BUFFER_SIZE] = {0};
         char* hello = "Hello from server";
         int valread; 
   
         while ((valread = recv(new_sock, buffer, MAX_BUFFER_SIZE, 0)) > 0)
         {
             printf("%s", buffer);
             send(new_sock, hello, strlen(hello), 0);
             //printf("Hello message sent\n");
         }
   
         if (valread < 0)
            exit_perr("recv failed");
   */
         close(ps_sock);
         close(new_sock);
      }
      close(sock);
      
   }
   return 0;
}
