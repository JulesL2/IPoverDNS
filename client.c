#include <fcntl.h>  /* O_RDWR */
#include <string.h> /* memset(), memcpy() */
#include <stdio.h>  /* perror(), printf(), fprintf() */
#include <stdlib.h> /* exit(), malloc(), free() */
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <arpa/inet.h>

#include "base64.h"
#include "fragmentation.h"
#include "getip.h"
#include "client.h"

int tun_open(char *devname)
{
    /*
     * Fonction qui ouvre l'interface tun et qui créé un file descriptor du socket ouvert
     *
     */

    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) == -1)
    {
        perror("open /dev/net/tun");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;      // Création d'un TUN et non d'un TAP, IFF_NO_PI permet de supprimé un header de 4 octets rajouté par l'interface qui donne 2 octets pour des flags et 2 octets pour le protocole (ipv4 ou ipv6 par exemple)
    strncpy(ifr.ifr_name, devname, IFNAMSIZ); // Si uyn nom est spécifié, alors on écrit le nom spécifié sur l'interface

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) == -1)
    {
        perror("ioctl TUNSETIFF");
        exit(1);
    }
    return fd;
}

int print_stream(int fd)
{
    /*
     *
     * Fonction utilisée pour afficher en héxa les paquets pour pouvoir comparer ce qu'on capture avec
     * des captures wireshark/tshark afin de mieux comprendre la structure des données qu'on capture
     * Ici l'encodage en base64 URL est testé
     *
     */
    int nbytes;
    char buf[1600];
    memset(&buf, '\0', 1600);
    while (1)
    {
        nbytes = read(fd, buf, sizeof(buf));

        printf("Read %d bytes from tun1\n", nbytes);
        for (int i = 0; i < nbytes; i++)
        {
            // Affichage du buffer en Hexa
            printf("%02X", (unsigned char)buf[i]);
        }
        printf("\n");

        size_t taille2 = (size_t)nbytes;

        // Encodage des données capturées
        char *resultat = base64_encode(buf, (size_t)taille2, &taille2);
        // Affichage
        printf("resultat \n%s \n", resultat);

        // Décodage des données capturées
        size_t taille = (size_t)strlen(resultat);
        unsigned char *decode = base64_decode(resultat, taille, &taille);
        if (decode == NULL)
        {
            printf("erreur décodage");
        }
        else
        {
            printf("taille %d\n", (int)taille);
            for (int i = 0; i < taille; i++)
            {
                printf("%02X", (unsigned char)decode[i]);
            }
            printf("\n");
        }
    }
    return 0;
}

int sendHost(unsigned char *hostname, int qtype, int sock_fd)
{
    /*
     * Fonction qui envoie la requete dns pour le hostname donné
     * Ainsi il suffit d'envoyer les données sous la forme xxxxx.t.lecoustre.org
     * où tunnel.lecoustre.org est un domaine que nous controlons.
     *
     */

    // Création des buffers utiles pour l'envoie et la reception
    unsigned char buf[65536], *query_name, *reponse;

    // Création de la structure dns
    struct DNS_HEADER *dns = NULL;
    dns = (struct DNS_HEADER *)&buf; // On rajoute l'header au début du buffer
    // paramétrage de l'header
    dns->id = (unsigned short)htons(rand()); // Pour fixer un identifiant on met le PID du prog
    dns->qr = 0;                             // Requête
    dns->opcode = 0;                         // Requete Standard
    dns->aa = 1;                             // Demande autorité (Comme notre server est celui qui fait authorité sur le domaine)
    dns->tc = 0;                             // Ce message n'est pas découpé
    dns->rd = 1;                             // On veut la récursion
    dns->ra = 0;
    dns->z = 0;

    dns->ad = 0;
    dns->cd = 0;

    dns->rcode = 0;
    dns->q_count = htons(1); // 1 question est posée dans le paquet
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // On se décale après le header DNS
    query_name = (unsigned char *)&buf[sizeof(struct DNS_HEADER)];

    // On converti le hostname en query name ie www.google.fr devient www3google6fr0
    ConvertDns(query_name, hostname);

    // Création de la structure de question pour y mettre nos données
    struct QUESTION *qinfo;
    qinfo = (struct QUESTION *)&buf[sizeof(struct DNS_HEADER) + (strlen((const char *)query_name) + 1)]; // fill it

    qinfo->qtype = htons(Req_TXT); // Requete de type TXT (On met la réponse dans le champs txt)
    qinfo->qclass = htons(1);      // Internet -> 1

    // Envoie de la requête
    // On utilise un socket qui a été connecté via connect() au serveur dns
    int nsend = send(sock_fd, (char *)buf, sizeof(struct DNS_HEADER) + (strlen((const char *)query_name) + 1) + sizeof(struct QUESTION), 0);
    if (nsend < 0)
    {
        printf("Erreur d'envoi\n");
        return -1;
    }
    return 0;
}

int recv_host(int sock_fd, unsigned char *retour, unsigned char (*raw_data)[][MAX_IPV4_SIZE], int nb_max, int *t_sortie)
{
    /*
     *   On recoit la réponse après l'envoie de la requete sur le nom de domaine
     *   Le serveur DNS créé une reponse à la question DNS posée de type TXT et insère dans le TXT le message de retour encodé
     *
     *
     */
    int k = 0;
    unsigned char buf2[MAX_IPV4_SIZE];
    char paquets_txt[MAX_PACKETS_NB][MAX_PACKET_SIZE];
    char *reponse;

    for (; k < nb_max; k++)
    {
        int nrecv = recv(sock_fd, buf2, MAX_IPV4_SIZE, 0);

        if (nrecv < 0)
        {
            printf("Erreur reception\n");
            return -1;
        }
        printf("Taille paquet recu : %d\n", nrecv);

        memcpy((*raw_data)[k], buf2, nrecv);
        // On récupère le header
        struct DNS_HEADER *dns2;
        dns2 = (struct DNS_HEADER *)buf2;
        unsigned char *query_name = &buf2[sizeof(struct DNS_HEADER)];
        reponse = &buf2[sizeof(struct DNS_HEADER) + (strlen((char *)query_name) + 1) + sizeof(struct QUESTION)];

        // Comme on est après la query, on est sur le début de la réponse on cast la structure answers pour récuperer les valeurs plus facilement
        struct ANSWERS *contenu = (struct ANSWERS *)reponse;

        // printf("Buffer recu :\n");
        // print_hexa(buf2,nrecv);

        reponse = reponse + sizeof(struct ANSWERS);
        memcpy(paquets_txt[k], reponse, ntohs(contenu->data_len) - 1);
        // printf("Taille txt: %d\n",ntohs(contenu->data_len)-1);

        int a = nbFragmentMax(&paquets_txt[k]);
        // int a = nbFragmentMax(reponse);
        if (a > 0)
        {
            nb_max = a + 1;
        }
        // printf("nbmax = %d \n",nb_max);
    }
    char retour_encode[MAX_IPV4_SIZE]; // Chaine de caractère correspondant au message retour encodé en base64

    // On rassemble les morceaux de texte
    rassembler(&paquets_txt, retour_encode, nb_max);

    printf("RESULTAT BASE64, t: %d\n%s\n", (int)strlen(retour_encode), retour_encode);
    // print_hexa(retour_encode,strlen(retour_encode));

    size_t taille_ret;
    // Décodage de la chaine de caractère encodée en base64
    unsigned char *test_ret = base64_decode(retour_encode, strlen(retour_encode), &taille_ret);
    int taille_retour = (int)taille_ret;
    printf("RESULTAT decode t:%d\n", taille_retour);
    print_hexa(test_ret, taille_retour);

    memcpy(retour, test_ret, taille_retour); // On copie sur la chaine de caractère de sortie le texte décodé
    retour[taille_retour + 1] = '\0';
    *t_sortie = taille_retour;
    return 0;
}

unsigned char *ReadName(unsigned char *reponse, unsigned char *buffer, int *count)
{
    /*
     *
     * SOURCE : https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
     *
     */

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

void ConvertDns(unsigned char *dns, unsigned char *host) // Conversion en format compressé
{
    /*
     *
     * SOURCE : https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
     *
     */
    int lock = 0, i;
    strcat((char *)host, ".");

    for (i = 0; i < strlen((char *)host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

int print_ip(int fd)
{
    /*
     *
     * Fonction qui affiche les données de la couche IPV4 a des fins de débuggage
     *
     */
    int nbytes;
    char buf[1600];
    struct IPV4 *reqip;
    while (1)
    {
        nbytes = read(fd, buf, sizeof(buf));

        reqip = (struct IPV4 *)&buf;
        printf("%02X %02X %04X %04X %04X %02X %02X %04X \n", reqip->hlength, reqip->service_field, ntohs(reqip->t_length), ntohs(reqip->identification), ntohs(reqip->flags), reqip->ttl, reqip->protocol, ntohs(reqip->checksum));
        printf("Source : %08X \n", ntohl(reqip->source));
        printf("Destination : %08X \n", ntohl(reqip->destination));
    }
    return 0;
}

void print_hexa(unsigned char *s, int len)
{
    /*
     *
     *   Fonction qui affiche le message de longueur len en hexadécimal: utilisé pour comparer les message reçu, émis et capturé
     *
     */
    for (int i = 0; i < len; i++)
    {
        printf("%02X", s[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{

    int fd, fd_tun;

    fd_tun = tun_open("tun1");
    printf("Device tun1 opened\n");

    // print_stream(fd_tun);

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Ouverture du socket sur le port 53 direction notre server dns
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_server); // dns servers

    // TEST CONNECT

    int co = connect(fd, (struct sockaddr *)&dest, sizeof(dest));
    if (co < 0)
    {
        printf("Erreur connect\n");
    }
    while (1)
    {

        unsigned char buf[MAX_IPV4_SIZE];
        unsigned char buf2[MAX_IPV4_SIZE];

        int condition = 1;
        int nbytes;
        uint8_t comparaison = 0xf0;
        // On s'assure de bien recevoir un ICMP IPV4
        while (condition == 1)
        {
            nbytes = read(fd_tun, buf, sizeof(buf));
            if ((buf[0] & comparaison) == (0x40 & comparaison))
            {
                struct IPV4 *header_ipv4 = (struct IPV4 *)&buf[0];
                if (header_ipv4->protocol = 1)
                {
                    condition = 0;
                }
            }
        }
        char *message_a_encoder = buf;
        // print_hexa(message_a_encoder, nbytes);
        size_t taille_enc = (size_t)nbytes;

        char *message_enc = base64_encode(message_a_encoder, taille_enc, &taille_enc);

        // printf("message encodé \n%s\n", message_enc);
        char frag[MAX_PACKETS_NB][MAX_PACKET_SIZE];

        // print_hexa(message_enc, strlen(message_enc));
        int nb_frag = decouper(message_enc, &frag);
        /*
        printf("premier fragment %d\n", strlen(frag[0]));
        print_hexa(frag[0], strlen(frag[0]));
        printf("deuxieme fragment %d\n", strlen(frag[1]));

        print_hexa(frag[1], strlen(frag[1]));
        printf("troisieme fragment %d\n", strlen(frag[2]));
        print_hexa(frag[2], strlen(frag[2]));
        */

        for (int i = 0; i < nb_frag; i++)
        {
            char host[64];
            strcpy(host, frag[i]);
            strcat(host, ".t.lecoustre.org"); // On ajoute le nom de domaine sur lequel on a autorité
            sendHost(host, Req_TXT, fd);
        }
        printf("Message envoyé\n");

        int nb_max_req = 5;
        unsigned char raw_data[nb_max_req][MAX_IPV4_SIZE];
        int taille_host;
        recv_host(fd, buf2, &raw_data, nb_max_req, &taille_host);
        printf("Message recu\n");
        // print_hexa(buf2,taille_host);

        // On envoie la réponse sur l'interface tun
        int nbretour = write(fd_tun, buf2, taille_host);
        printf("Message retourné sur tun0\n");
        // printf("%d %d\n",nbretour,taille_host);
    }
}