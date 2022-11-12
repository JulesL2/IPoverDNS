#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <errno.h>
#include <unistd.h>

#include "server.h"
#include "getip.h"
#include "base64.h"
#include "fragmentation.h"

// Fonctionnement de l'header
// http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
// http://www.networksorcery.com/enp/protocol/dns.htm

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
    unsigned char z : 1;       // reservé pour une utilisation plus tard
    unsigned char ra : 1;      // recursion dispo
    unsigned short q_count;    // nb questions
    unsigned short ans_count;  // nb réponses
    unsigned short auth_count; // nb authoritative
    unsigned short add_count;  // nb ressources
};

// Création de la structure ANSWERS pour écrire facilement les réponses TXT du server

struct ANSWERS_TXT
{
    unsigned short offset;
    unsigned short type;
    unsigned short class;
    unsigned short ttl1;
    unsigned short ttl2;
    unsigned short data_len;
    unsigned char txt_len;
};

// structure IPV4

struct IPV4
{
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

unsigned char *ReadName(unsigned char *reponse, unsigned char *buffer, int *count)
{
    // SOURCE : https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char *)malloc(256);

    name[0] = '\0';

    // read the names in 3www6google3com format
    while (*reponse != 0)
    {
        if (*reponse >= 192)
        {
            offset = (*reponse) * 256 + *(reponse + 1) - 49152; // 49152 = 11000000 00000000 ;)
            reponse = buffer + offset - 1;
            jumped = 1; // we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *reponse;
        }

        reponse = reponse + 1;

        if (jumped == 0)
        {
            *count = *count + 1; // if we havent jumped to another location then we can count up
        }
    }

    name[p] = '\0'; // string complete
    if (jumped == 1)
    {
        *count = *count + 1; // number of steps we actually moved forward in the packet
    }

    // now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int)strlen((const char *)name); i++)
    {
        p = name[i];
        for (j = 0; j < (int)p; j++)
        {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; // remove the last dot
    return name;
}

int estDansTableau(unsigned char *tab, int taille, unsigned char a)
{
    // Renvoie 1 si dans le tableau 0 sinon
    int i = 0;
    while (i < taille && tab[i] != a)
    {
        i++;
    }
    if (i < taille)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int recv_frag_packets(int fd, unsigned char (*buffer_dns)[][MAX_DNS_SIZE], char (*donnees_frag)[][MAX_PACKET_SIZE], int (*fin_dns)[MAX_PACKETS_NB], int k_max, struct sockaddr_in *client, int (*taille_fragments)[MAX_PACKETS_NB])
{
    /*
     *
     * Cette fonction est destinée a receptionner l'ensemble des paquets fragmentés pour les mettres dans un tableau
     * Du coté du server
     */
    unsigned char copie_dns[MAX_PACKETS_NB][MAX_DNS_SIZE];
    socklen_t slen = sizeof(struct sockaddr_in);
    int k = 0;
    unsigned char id[k_max];
    memset(id, '\0', k_max);
    int counter_failure = 0;
    for (; k < k_max + 1; k++)
    {

        // On recoit le traffic qui essaye de sortir de la machine
        int nbytes = recvfrom(fd, (*buffer_dns)[k], 65000, 0, (struct sockaddr *)client, &slen);
        if (nbytes < 0)
        {
            printf("Erreur reception DNS %s", strerror(errno));
            return -1;
        }
        // printf("NBYTES %d MESG HEXA\n",nbytes);
        // print_hexa((*buffer_dns)[k],nbytes);
        memcpy(copie_dns[k], (*buffer_dns)[k], nbytes);
        copie_dns[k][nbytes + 1] = '\0';
        // Extraction des données :
        unsigned char *query_name = &copie_dns[k][(sizeof(struct DNS_HEADER))];

        // Le décalage pour le nom est initialisé
        int stop = 0;

        // Lecture du nom et décalage du pointeur après le nom (donnees =  xxxxxx.tunnel.lecoustre.org puis on découpe pour que donnees = xxxxxxx)
        char *donnees;
        donnees = ReadName(query_name, copie_dns[k], &stop);

        struct fragmentationHeader *header;
        header = (struct fragmentationHeader *)&donnees;

        // printf("frag id %02X\n",header->fragmentId);
        unsigned char identifiant = (unsigned char)header->fragmentId;
        if (estDansTableau(id, k_max, identifiant) == 0)
        {
            // On ne traite que les fragments qui n'ont pas encore été traité
            id[k] = identifiant;
            stop += 4; // On ajoute 4 à stop pour se décaler après toute la query
            (*fin_dns)[k] = stop;
            // La query est constituée du nom de domaine + de 2 octet pour le type et 2 octets pour la classe donc on se décale de 4 octets supplémentaires

            // exclusion du nom de domaine
            size_t len_donnees = (size_t)0;
            for (int j = 0; j < nbytes; j++)
            {
                if (donnees[j] == '.')
                {
                    donnees[j] = '\0';
                    len_donnees = (size_t)j;
                    break;
                }
            }

            // On ajoute dans les tableaux les données importantes
            strcpy((*donnees_frag)[k], donnees);
            (*fin_dns)[k] = stop;
            (*taille_fragments)[k] = (int)len_donnees;

            // RECUPERATION DU NOMBRE DE PACKETS
            int a = nbFragmentMax(&(*donnees_frag)[k]);
            if (a > k_max)
            {
                printf("Erreur k_max fragments\n");
            }
            if (a > 0)
            {
                k_max = a;
            }
            // printf("kmax = %d \n",k_max);
        }
        else
        {
            counter_failure += 1;
        }
        if (counter_failure >= k_max)
        {
            perror("Impossible de recevoir tous les fragments !\n");
            exit(1);
        }
    }

    return k;
}

int send_dns_answers(int fd, unsigned char (*buffer_dns)[][MAX_DNS_SIZE], char (*donnees_frag)[][MAX_PACKET_SIZE], int (*fin_dns)[], int nb_fragment, struct sockaddr_in *client)
{
    socklen_t slen = sizeof(struct sockaddr_in);
    int i = 0;
    for (; i < nb_fragment; i++)
    {
        // On récupère le header
        struct DNS_HEADER *dns = (struct DNS_HEADER *)(*buffer_dns)[i];
        // Passage du header en mode réponse
        dns->qr = 1;
        // Passage du nombre de réponse sur 1
        dns->rd = 0;
        dns->aa = 1; // On indique que la réponse est authoritative
        dns->ans_count = htons(1);
        dns->add_count = htons(0);
        dns->rcode = htons(0); // On indique qu'il n'y a pas d'erreurs

        // print_hexa(dns,sizeof(struct DNS_HEADER));

        // On positionne la structure
        struct ANSWERS_TXT *answer = (struct ANSWERS_TXT *)&(*buffer_dns)[i][sizeof(struct DNS_HEADER) + (*fin_dns)[i]]; // On se positionne juste après la query

        answer->offset = htons(49164); // Correspond à C0 0C (1100 0000 0000 1100) => deux premiers 1 : signale que c'est l'offset puis on pose la distance
        // par rapport au début du paquet DNS, du coup cela signifie que la réponse concerne l'ensemble du domaine envoyé en entrée
        answer->type = htons(16); // Type TXT
        answer->class = htons(1); // Class IN : Internet
        answer->ttl1 = htons(0);  // Pour le TTL, le format DNS spécifie 4 octets mais il y avait un bug sur le type uint_32t ne fonctionnait pas,
        answer->ttl2 = htons(5);  // Un paquet de 6 octets était systématiquement créé. Ainsi une solution a été de mettre 2 short pour fabriquer 4 octets
        int txt_len = strlen((*donnees_frag)[i]);
        answer->data_len = htons(txt_len + 1); // Longueur de la donnée (= longueur du texte +1 pour l'octet qui donne la longueur du texte)
        answer->txt_len = (unsigned char)(txt_len);

        memcpy(&(*buffer_dns)[i][sizeof(struct DNS_HEADER) + (*fin_dns)[i] + sizeof(struct ANSWERS_TXT)], (*donnees_frag)[i], txt_len);

        int taille_tot = sizeof(struct DNS_HEADER) + (*fin_dns)[i] + sizeof(struct ANSWERS_TXT) + txt_len;

        // printf("reponse :\n");
        // print_hexa( (*buffer_dns)[i],taille_tot);
        // printf("fragment txt %s\n",(*donnees_frag)[i]);

        int nb_reponse = sendto(fd, (*buffer_dns)[i], taille_tot, 0, (struct sockaddr *)client, slen);
        printf("Réponse DNS : %d Bytes envoyés\n", nb_reponse);

        if (nb_reponse < 0)
        {
            printf("ERREUR ENVOIE REPONSE DNS %s\n", strerror(errno));
            return -1;
        }
    }
    return i;
}

void print_hexa(unsigned char *s, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02X", s[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    char buffer[65000];

    // ETH0 BUFFER
    unsigned char buf_eth0[BUF_SIZE]; // buffer eth0
    memset(&buf_eth0, '\0', BUF_SIZE);

    // CREATION SOCKETS
    //
    //*****************************************************************************************************//
    // Socket d'écoute du traffic DNS
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        printf("Erreur Socket DNS");
    }

    // Socket de transfert et de reception du message//
    int fd_raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd_raw < 0)
    {
        printf("Erreur Socket RAW %s", strerror(errno));
    }
    int one = 1;
    const int *val = &one;

    setsockopt(fd_raw, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
    const char *interface;
    interface = "enp0s3"; // A modifier pour chaque machine : correspond à la carte ethernet
    setsockopt(fd_raw, SOL_SOCKET, SO_BINDTODEVICE, interface, sizeof(interface));
    //*****************************************************************************************************//

    // BIND SOCKET DNS
    //
    //*****************************************************************************************************//
    // Server DNS et client DNS parametrage structure pour les sockets bind et recvfrom
    struct sockaddr_in server_dns, client;
    memset(&server_dns, 0, sizeof(struct sockaddr_in));
    memset(&client, 0, sizeof(struct sockaddr_in));
    server_dns.sin_family = AF_INET;
    server_dns.sin_addr.s_addr = INADDR_ANY;
    server_dns.sin_port = htons(53); // Port 53 : standard pour les requêtes DNS
    socklen_t socklen = sizeof(struct sockaddr_in);

    // Server SOCK_RAW
    struct sockaddr_in ipv4_server_raw; // structure d'écoute du server sur eth0
    memset(&ipv4_server_raw, 0, sizeof(ipv4_server_raw));
    ipv4_server_raw.sin_family = AF_INET;
    ipv4_server_raw.sin_port = htons(0);
    ipv4_server_raw.sin_addr.s_addr = INADDR_ANY;

    // Bind Socket DNS sur le port 53
    int b = bind(fd, (const struct sockaddr *)&server_dns, socklen);
    if (b < 0)
    {
        printf("Erreur Bind DNS %s\n", strerror(errno));
    }
    //*****************************************************************************************************//

    unsigned char *reponse;
    while (1)
    {
        // Réception des paquets fragmentés
        int nb_max_paquets = MAX_PACKETS_NB;
        int points_arrets[MAX_PACKETS_NB];
        unsigned char(*buffer_dns)[MAX_PACKETS_NB][MAX_DNS_SIZE] = malloc((MAX_PACKETS_NB + 2) * MAX_DNS_SIZE * sizeof(char));
        char fragments[MAX_PACKETS_NB][MAX_PACKET_SIZE];
        int taille_fragments[MAX_PACKETS_NB];
        int nb_frag = recv_frag_packets(fd, buffer_dns, &fragments, &points_arrets, nb_max_paquets, &client, &taille_fragments);
        unsigned char(*test_dns)[MAX_PACKETS_NB][MAX_DNS_SIZE] = malloc((MAX_PACKETS_NB + 2) * MAX_DNS_SIZE * sizeof(char));

        printf("Nb frag received %d\n", nb_frag);

        // Défragmentation
        char *donnees_defragmentees = malloc((size_t)(MAX_IPV4_SIZE));
        // print_hexa(fragments[0],strlen(fragments[0]));
        // print_hexa(fragments[1],strlen(fragments[1]));
        // print_hexa(fragments[2],strlen(fragments[2]));
        // print_hexa(fragments[nb_max_paquets-1],strlen(fragments[nb_max_paquets-1]));
        /*for (int a = 0; a < nb_frag; a++)
        {
            print_hexa(fragments[a], strlen(fragments[a]));
        }*/

        int er = rassembler(&fragments, donnees_defragmentees, nb_frag);
        if (er < 0)
        {
            printf("Erreur défragmentation");
        }
        // printf("Donnees defrag\n%s\n",donnees_defragmentees);

        // Décodage BASE64URL

        /*
        char donnees_decode[MAX_IPV4_SIZE];
        size_t taille_decode = (size_t)MAX_IPV4_SIZE;
        size_t *taille_dec = &taille_decode;
        //size_t len_donnees = strlen(donnees_defragmentees);
        size_t len_donnees = nb_frag*MAX_PACKET_SIZE;
        base64decode(donnees_defragmentees, len_donnees, donnees_decode, taille_dec);
        */

        // char donnees_decode[MAX_IPV4_SIZE];
        size_t taille_decode = (size_t)MAX_IPV4_SIZE;
        size_t *taille_dec = &taille_decode;
        size_t len_donnees = strlen(donnees_defragmentees);
        printf("Input len %d\n", (int)len_donnees);
        unsigned char *donnees_decode = base64_decode(donnees_defragmentees, (size_t)len_donnees, taille_dec);
        // print_hexa(donnees_decode, *taille_dec);

        free(donnees_defragmentees);

        // Récupération de l'ip locale:
        struct sockaddr_in *ip_loc;
        ip_loc = getlocalip();

        // Récupération IP Header
        struct IPV4 *reqip = (struct IPV4 *)(donnees_decode); // Cast de la réponse dans la structure IPV4 header

        // Récupération de la destination pour lui envoyer le paquet
        struct sockaddr_in destinataire; // Destinataire sur le réseaux (exemple : 1.1.1.1)
        destinataire.sin_family = AF_INET;
        // MODIFIER SIN_ADDR DESTINATION AVEC L'IP DEST DE STRUCT IPV4

        // DEBUGGAGE

        destinataire.sin_addr.s_addr = reqip->destination;

        //  STOCKER L'IP SOURCE POUR LE METTRE EN IP DEST AU RETOUR
        uint32_t ip_source_bits = reqip->source;

        //  MODIFIER L'IP SOURCE PAR L'IP LOCALE
        reqip->source = ip_loc->sin_addr.s_addr;

        // Envoie sur eth0 de la requete capturé sur tun0 en raw packet puisqu'on a le paquet IPV4 et qu'on a mis l'option IP_HDRINCL sur 1 donc on fournit l'header
        int n_b_envoyes = sendto(fd_raw, donnees_decode, taille_decode, 0, (struct sockaddr *)&destinataire, (socklen_t)sizeof(struct sockaddr));
        if (n_b_envoyes < 0)
        {
            printf("ERREUR ENVOIE !!!  %s\n", strerror(errno));
        }
        printf("%d bytes sent \n", n_b_envoyes);

        // Reception de la réponse
        socklen_t len_raw = sizeof(struct sockaddr_in);
        int nb_recv = recvfrom(fd_raw, buf_eth0, BUF_SIZE, 0, (struct sockaddr *)&ipv4_server_raw, &len_raw);
        if (nb_recv < 0)
        {
            printf("ERREUR RECEPTION !!!  %s\n", strerror(errno));
        }
        printf("Received %d bytes \n", nb_recv);

        // print_hexa(buf_eth0, nb_recv);

        // Lecture du paquet IPv4 reçu :
        //  Modification de la destination pour remettre l'ip source du client de l'autre coté du tunnel
        struct IPV4 *reponse_ipv4 = (struct IPV4 *)buf_eth0;
        reponse_ipv4->destination = ip_source_bits;

        struct sockaddr_in expediteur; // Expéditeur du message de l'autre coté du tunnel : le Client
        memset(&expediteur, 0, sizeof(struct sockaddr_in));
        expediteur.sin_family = AF_INET;
        expediteur.sin_addr.s_addr = ip_source_bits;

        // Encodage du message en Base64 :
        size_t taille_enc = (size_t)nb_recv;
        char *url_resultat = base64_encode(buf_eth0, taille_enc, &taille_enc);
        // printf("resultat\n%s\n", url_resultat);

        // Fragmentation
        char paquets[MAX_PACKETS_NB][MAX_PACKET_SIZE];
        int nb_frag_emis = decouper(url_resultat, &paquets);
        if (nb_frag_emis < 0)
        {
            printf("Erreur fragmentation");
        }
        printf("Nb de fragments sent %d\n", nb_frag_emis);
        /*
        for (int a = 0; a < nb_frag_emis; a++)
        {
            printf("fragment %d   l: %d\n", a, strlen(paquets[a]));
            print_hexa(paquets[a], strlen(paquets[a]));
        }
        */
        // Comme on ne dispose que de nb_frag requetes DNS on ne peut répondre que nb_frag fois
        if (nb_frag_emis <= nb_frag)
        {
            printf("Pas erreur sur nb fragments\n");
            nb_frag = nb_frag_emis;
        }
        // Envoie de la/des requete(s) DNS avec le message en base 64
        int t_tot = sizeof(struct DNS_HEADER) + points_arrets[0] + sizeof(struct ANSWERS_TXT) + strlen(paquets[0]);
        send_dns_answers(fd, buffer_dns, &paquets, &points_arrets, nb_frag, &client);
        printf("DNS answers sent\n\n");
    }
}