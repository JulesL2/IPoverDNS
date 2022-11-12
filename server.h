#ifndef SERVER_H
#define SERVER_H

#define BUF_SIZE 1600

// Type de requete dns
#define Req_A 1    // requete type A IPv4
#define Req_TXT 16 // Requete TXT

// Fragmentation
#define MAX_PACKETS_NB 4   // On admet qu'on fragmente au maximum sur X paquets
#define MAX_PACKET_SIZE 48 // Le paquet fragmenté a pour taille max 48 octets car le nom de domaine fait 64 octets max
#define MAX_IPV4_SIZE 2500 // Le paquet IPV4 doit faire moins de 2500 octets
#define MAX_DNS_SIZE 512

unsigned char *ReadName(unsigned char *reponse, unsigned char *buffer, int *count);

int estDansTableau(unsigned char *tab, int taille, unsigned char a);

int recv_frag_packets(int fd, unsigned char (*buffer_dns)[][MAX_DNS_SIZE], char (*donnees_frag)[][MAX_PACKET_SIZE], int (*fin_dns)[MAX_PACKETS_NB], int k_max, struct sockaddr_in *client, int (*taille_fragments)[MAX_PACKETS_NB]);

void print_hexa(unsigned char *s, int len);

int send_dns_answers(int fd, unsigned char (*buffer_dns)[][MAX_DNS_SIZE], char (*donnees_frag)[][MAX_PACKET_SIZE], int (*fin_dns)[], int nb_fragment, struct sockaddr_in *client);

int print_stream(int fd);

#endif