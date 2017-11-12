#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/aes.h>
/*
 * pbproxy [-l port] -k keyfile destination port
 */


#define MAX_BUFFER_SIZE 1024
#define MAX_KEY_SIZE 16

struct ctr_state
{
   unsigned char ivec[16];
   unsigned int num;
   unsigned char ecount[16];
};

int init_ctr(struct ctr_state* state, unsigned char iv[8])
{
   state->num = 0;
   memset(state->ecount, 0, 16);
   memset(state->ivec+8,0,8);
   memcpy(state->ivec, iv, 8);
}

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
   unsigned char  key[MAX_KEY_SIZE+1] = {0};
   int   opt;
   int   client = 1;
   char* temp;
   char  buffer[MAX_BUFFER_SIZE+1] = {0};
   char  ebuf[MAX_BUFFER_SIZE+1] = {0};

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
      if (strcmp(destaddr, "localhost") == 0)
         strcpy(destaddr,"127.0.0.1");
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
   else
   {
      int i;
      FILE* fp = fopen(keyfile, "r");
      unsigned char temp[32+1];

      if (fp == NULL)
      {
         exit_err("Unable to open key file");
      }

      fgets(temp, 33, fp);

      if (strlen(temp) < 32)
         exit_err("Key should be hexa-decimal form with atleast 32 characters");

      for (i = 0;i < 16;i++)
         sscanf(temp+2*i, "%2hhx", &key[i]);

      /*for (i = 0;i < 16;i++)
         printf("%d ",(int) key[i]);
      printf("\n");*/
      fclose(fp);
   }

   if (!destaddr)
   {
      exit_err("Destination IP is mandatory");
   }

   if (dport == -1)
   {
      exit_err("destination_port is mandatory");
   }

   //printf("key - %s, destip = %s, lport = %d, dport = %d\n", key, destaddr, lport, dport);

   /********* Input parsing done *************/


   if (client)
   {
      int sock;
      int bytes;
      struct sockaddr_in server_addr ; 
      fd_set dset;
      struct ctr_state en_state;
      struct ctr_state dec_state;
      AES_KEY aes_key;
      unsigned char e_iv[8];
      unsigned char d_iv[8];

      if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      {
         exit_perr("Unable to create socket");
      }
   
      memset(&server_addr, '0', sizeof(server_addr));
   
      server_addr.sin_family = AF_INET;
      server_addr.sin_addr.s_addr = inet_addr(destaddr);
      server_addr.sin_port = htons(dport);
  
      /* Connect to the pbproxy server */ 
      if (connect(sock, (const struct sockaddr*)&server_addr, sizeof(server_addr)))
         exit_perr("Connection failed");

      /* Exchange IV with the pb-server
       * pb-client sends an IV to the pb-server
       * and waits for the IV for the stream from the other direction */   
      if (!RAND_bytes(e_iv, 8))
         exit_err("Unable to use RAND");

      /* Send IV to the server*/
      write(sock, e_iv, 8);
      /* Receive IV to the server*/
      if (read(sock,d_iv, 8) != 8)
         exit_err("IV exchange failed");
      
      init_ctr(&en_state, e_iv);
      init_ctr(&dec_state, d_iv);

      if (AES_set_encrypt_key(key, 128, &aes_key) < 0)
         exit_err("AES_set_encrypt_key fail");

      /* Start talking */
      while (1){
         FD_ZERO(&dset);
         FD_SET(STDIN_FILENO, &dset);
         FD_SET(sock, &dset);
         select(sock+1, &dset, NULL, NULL, NULL);
   
         if (FD_ISSET(sock, &dset))
         {
            bytes = read(sock, buffer, MAX_BUFFER_SIZE);
            if (bytes == 0)
               break;

            AES_ctr128_encrypt(buffer, ebuf, bytes, 
                      &aes_key, dec_state.ivec, dec_state.ecount, 
                      &dec_state.num);
            write(STDOUT_FILENO, ebuf, bytes);
         }
   
         if (FD_ISSET(STDIN_FILENO, &dset))
         {
            bytes = read(STDIN_FILENO, buffer, MAX_BUFFER_SIZE);
            if (bytes == 0)
               break;

            AES_ctr128_encrypt(buffer, ebuf, bytes, 
                      &aes_key, en_state.ivec, en_state.ecount, 
                      &en_state.num);
            write(sock, ebuf, bytes);
         }
      }
      close(sock);
   }
   else
   {
      int new_sock, sock, opt = 1;
      int len;
      int bytes;
      struct sockaddr_in server_addr ; 
      int ps_sock; // proxy server sock
      struct sockaddr_in ps_server_addr ; 
      fd_set dset;
      struct ctr_state en_state;
      struct ctr_state dec_state;
      AES_KEY aes_key;
      unsigned char e_iv[8];
      unsigned char d_iv[8];

      if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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
   
      while(1)
      {
         if ((new_sock = accept(sock, (struct sockaddr*)&server_addr,
                                (socklen_t*)&len)) <0)
            exit_perr("accept failed");
 
         /* Exchange crypto-information */ 
         if (!RAND_bytes(e_iv, 8))
            exit_err("Unable to use RAND");
  
         /* Send IV to the client */ 
         write(new_sock, e_iv, 8);
         /* Receive IV from the client */ 
         if (read(new_sock,d_iv, 8) != 8)
            exit_err("IV exchange failed");
         
         init_ctr(&en_state, e_iv);
         init_ctr(&dec_state, d_iv);

         if (AES_set_encrypt_key(key, 128, &aes_key) < 0)
            exit_err("AES_set_encrypt_key fail");

         //printf("\n\n\nNew client \n");
         if ( (ps_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
         {
            exit_perr("Unable to create pssocket");
         }
   
         memset(&ps_server_addr, '0', sizeof(ps_server_addr));
   
         ps_server_addr.sin_family = AF_INET;
         ps_server_addr.sin_addr.s_addr = inet_addr(destaddr);
         ps_server_addr.sin_port = htons(dport);
   
         if (connect(ps_sock, (const struct sockaddr*)&ps_server_addr, sizeof(ps_server_addr)))
            exit_perr("Connection failed");
   
         while (1)
         {
            FD_ZERO(&dset);
            FD_SET(ps_sock, &dset);
            FD_SET(new_sock, &dset);
   
            select(max(ps_sock, new_sock)+1, &dset, NULL, NULL, NULL);
   
            if (FD_ISSET(ps_sock, &dset))
            {
               bytes = read(ps_sock, buffer, MAX_BUFFER_SIZE);
               if (bytes == 0)
               {
                  break;
               }
               AES_ctr128_encrypt(buffer, ebuf, bytes, 
                      &aes_key, en_state.ivec, en_state.ecount, 
                      &en_state.num);
               send(new_sock, ebuf, bytes, 0);
               //ebuf[bytes] = 0;
               //printf("bytes = %d, Right -> Left : %s\n", bytes, ebuf);
            }
   
            if (FD_ISSET(new_sock, &dset))
            {
               bytes = read(new_sock, buffer, MAX_BUFFER_SIZE);
               if (bytes == 0)
               {
                  break;
               }
               AES_ctr128_encrypt(buffer, ebuf, bytes, 
                      &aes_key, dec_state.ivec, dec_state.ecount, 
                      &dec_state.num);
               send(ps_sock, ebuf, bytes, 0);
               //ebuf[bytes] = 0;
               //printf("bytes = %d, Left -> Right : %s\n", bytes, ebuf);
            }
         }
   
         close(ps_sock);
         close(new_sock);
      }
      close(sock);
      
   }
   return 0;
}
