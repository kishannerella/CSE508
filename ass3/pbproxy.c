#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
/*
 * pbproxy [-l port] -k keyfile destination port
 */


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
   char pstr[1024] = "";
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

int main(int argc, char **argv)
{

   int   lport = -1;
   int   dport = -1;
   char* destaddr = NULL;
   char* keyfile = NULL;
   int   opt;
   int   client = 1;
   char* temp;

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
   struct sockaddr_in server_addr ; /* In case of client pbproxy
       the server is server pbproxy. In case of server pbproxy
       the server means the ssh server */
   if ( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
   {
      exit_perr("Unable to create socket");
   }

   memset(&server_addr, '0', sizeof(server_addr));

   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons(dport);

   if (inet_pton(AF_INET, destaddr, &server_addr.sin_addr) <=0)
      exit_perr("Invalid address");

   if (connect(sock, (const struct sockaddr*)&server_addr, sizeof(server_addr)))
      exit_perr("Connection failed");

   char* hello = "Hello from client";
   char buffer[1024] = {0};
   send(sock, hello, strlen(hello), 0);
   printf("Hello message sent\n");
   int valread = read(sock, buffer, 1024);
   printf("%s\n", buffer);
   close(sock);
}
else
{
   int new_sock, sock, opt = 1;
   int len;
   struct sockaddr_in server_addr ; 
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

   if ((new_sock = accept(sock, (struct sockaddr*)&server_addr,
                          (socklen_t*)&len)) <0)
      exit_perr("accept failed");

   char buffer[1024] = {0};
   char* hello = "Hello from server";
   int valread = read(new_sock, buffer, 1024);
   printf("%s\n", buffer);
   send(new_sock, hello, strlen(hello), 0);
   printf("Hello message sent\n");
   close(sock);
   
}
   return 0;
}
