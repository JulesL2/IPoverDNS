#ifndef CLIENT_H
#define CLIENT_H
#include <stdint.h>

// Type de requete dns
#define Req_A 1    // requete type A IPv4
#define Req_TXT 16 // Requete TXT

// Fragmentation
#define MAX_PACKETS_NB 3   // On admet qu'on fragmente au maximum sur X paquets
#define MAX_PACKET_SIZE 48 // Le paquet fragmenté a pour taille max 48 octets car le nom de domaine fait 64 octets max
#define MAX_IPV4_SIZE 2500 // Le paquet IPV4 doit faire moins de 2500 octets

// Fonctions
void ConvertDns(unsigned char *, unsigned char *);
unsigned char *ReadName(unsigned char *, unsigned char *, int *);

struct IPV4
{
    // unsigned char proto_ip[8];
    unsigned char hlength;
    unsigned char service_field;
    unsigned short t_length;
    unsigned short identification;
    unsigned short flags;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    uint32_t source;
    uint32_t destination;
};

// Structure de Header
struct DNS_HEADER
{
    unsigned short id;         // identification number
    unsigned char rd : 1;      // récursion
    unsigned char tc : 1;      // truncated message
    unsigned char aa : 1;      // authoritive answer
    unsigned char opcode : 4;  // opcode
    unsigned char qr : 1;      // query/response flag
    unsigned char rcode : 4;   // response code
    unsigned char cd : 1;      // checking disabled
    unsigned char ad : 1;      // authenticated data
    unsigned char z : 1;       //
    unsigned char ra : 1;      // recursion available
    unsigned short q_count;    // nb questions
    unsigned short ans_count;  // nb réponses
    unsigned short auth_count; // nb authoritative
    unsigned short add_count;  // nb ressources
};

struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

// Création de la structure ANSWERS pour lire plus rapidement les réponses

struct ANSWERS
{
    unsigned short offset;
    unsigned short type;
    unsigned short _class;
    unsigned short ttl1;
    unsigned short ttl2;
    unsigned short data_len;
    unsigned char txt_len;
};

// Structure of a Query
struct QUERY
{
    unsigned char *name;
    struct QUESTION *ques;
};

// Le server dns, a priori seul le dns 129.104.30.41 de l'X marche sur eduroam
// Pour ne pas a avoir a traité le cas complexe des requêtes récursives, on met le serveur en tant que serveur dns
// const char dns_server[50] = "129.104.30.41";
const char dns_server[50] = "92.132.194.84";

int tun_open(char *devname);
int print_stream(int fd);
int sendHost(unsigned char *hostname, int qtype, int sock_fd);
int recv_host(int sock_fd, unsigned char *retour, unsigned char (*raw_data)[][MAX_IPV4_SIZE], int nb_max, int *t_sortie);
unsigned char *ReadName(unsigned char *reponse, unsigned char *buffer, int *count);
void ConvertDns(unsigned char *dns, unsigned char *host);
int print_ip(int fd);
void print_hexa(unsigned char *s, int len);

#endif