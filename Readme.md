# IP Over DNS

In my project, I am implementing a tunneling through DNS requests.

## Architecture

### Principle :

The approach is the following:

On the client, we open a tun interface **tun1**. Then we capture everything that comes in this interface. As we are working with DNS requests, the data must be **text that is allowed in URL**. Therefore we encode the packet in **Base64URL**. Once the packet is encoded, it can be too long for DNS queries so we create fragment to respect the maximum size. Then we send all these fragment as TXT queries to the domain _xxxxxxx.t.lecoustre.org_ (where _xxxx_ is the data encoded in base64) and wait for the answers.

On the server side, we receive the packet on port 53, we defragment and decode the packet. Edit the source IP in the IP header and send it to internet via a **RAW_SOCKET**. Then we receive the answers and encapsulate the answers in the answer section of the incoming DNS queries which are sent back to the client.

Then the client get the answer and write it on **tun1**

Here is a diagram of the system:

![schema](/INF472Dschema.png "schema")

## Code

The code is divided in multiple programs:

- Utilities
- The server
- The client

## Utilities

---

In order to have a working program, we've needed several programs :

> **getip.c**

This program has 2 functions useful for our code:

```c
struct sockaddr_in* getip(void);
```

Return the external ip using the _wgetX_ code made in the tutorial

```c
struct sockaddr_in* getlocalip(void);
```

Return the internal ip

&nbsp;

> **base64.c**

This program is taken from wikipedia, the only edit made is the transformation of the **base64** algorithm to **base64URL** (_ie "/" and "+" replaced by "-" and "\_"_)

The table :

```c
static char encoding_table[]
```

contains the 64 characters used to do the encoding (6 bits used in base64 and 2^6 = 64)

```c
void build_decoding_table()
```

creates the table that matches index and characters

```c
char *base64_encode(const unsigned char *data,size_t input_length,size_t *output_length)
```

Returns the encoded string and write the output_length in the pointer `output_length`

```c
unsigned char *base64_decode(const char *data,size_t input_length,size_t *output_length)
```

Returns the decode string and write the output_length in the pointer `output_length`

> **fragmentation.c**

```c
int rassembler(char paquets[][48], char* T, int nbFragments);//reassemble packets to form the string T
int decouper(char *T, char (*paquets)[][48]); //cut the buffer T in fragments stored in paquet
int nbFragmentMax(char (*paquet)[48]); //return the maximum amount of fragments
int knuthShuffle(char (**paquets)[48], int nbFragments);//Only used for tests
```

> **tun.sh**

This file opens the tun1 interface, activate it and link it with 10.0.0.1/24 subnet. It must be run by a user with **CAP_NET** capacities.

It contains the following code

```bash
#!bin/bash
openvpn --mktun --dev tun1
ip link set tun1 up
ip addr add 10.0.0.1/24 dev tun1
```

## The Server

---

The functions of **server.c** are the following

```c
unsigned char *ReadName(unsigned char *reponse, unsigned char *buffer, int *count);
```

Reads the domain name of the query (support the DNS compression scheme), returns the domain

```c
int estDansTableau(unsigned char *tab, int taille, unsigned char a);
```

Returns 1 if the `char a` is in the table return 0 otherwise

```c
int recv_frag_packets(int fd, unsigned char (*buffer_dns)[][MAX_DNS_SIZE], char (*donnees_frag)[][MAX_PACKET_SIZE], int (*fin_dns)[MAX_PACKETS_NB], int k_max, struct sockaddr_in *client, int (*taille_fragments)[MAX_PACKETS_NB]);
```

Receive the fragmented packets and put the queries in _buffer_dns_, the fragments in _donnees_frag_ and the breakpoint for the domain name in _fin_dns_ and the fragment length in _taille_fragments_.

It takes as an argument a socket file descriptor : _fd_ and the maximum number of fragment allowed _k_max_

```c
void print_hexa(unsigned char *s, int len);
```

Function used to debug and print unsigned char data in hexadecimal : prints _len_ bytes.

```c
int send_dns_answers(int fd, unsigned char (*buffer_dns)[][MAX_DNS_SIZE], unsigned char (*donnees_frag)[][MAX_PACKET_SIZE], int (*fin_dns)[], int nb_fragment, struct sockaddr_in *client);
```

Send to _client_ the data in _donnees_frag_ that are encapsulate in _buffer_dns_ queries.

```c
int print_stream(int fd);
```

Function that print the stream in hexedecimal of the socket fd. Used to debug what comes in the socket of the interface **tun1**.

## The Client

---

The following functions are the same for the server and the client program.

```c
unsigned char *ReadName(unsigned char *, unsigned char *, int *);
int print_stream(int fd);
void print_hexa(unsigned char *s, int len);
```

&nbsp;

```c
int tun_open(char *devname);
```

Open the tun interface with the name _devname_.

```c
void ConvertDns(unsigned char *, unsigned char *);
```

Create the DNS in the compressed format

```c
int sendHost(unsigned char *hostname, int qtype, int sock_fd)
```

Function that send a DNS query with the hostname _hostname_ the type of the query is _qtype_ which is here _TXT_ and it is sent on the socket _sock_fd_

```c
int recv_host(int sock_fd, unsigned char *retour, unsigned char (*raw_data)[][MAX_IPV4_SIZE], int nb_max,int* t_sortie)
```

Function that received on _sock_fd_ the answers from the DNS server and that write the answers on _raw_data[][]_ then reassemble the packets and decode the string to return an unsigned char buffer : _retour_ _t_sortie_ is the size of retour and the argument _nb_max_ is the maximum number of fragments that can be received by the program.

```c
int print_ip(int fd)
```

Print data of the IP layer, used to debug the code.

## How to make things work :

---

### On the client side :

First we need to start **tun1** so we need to launch the tun.sh program.

```
sudo bash tun.sh
```

Then we need to choose the address we will send ping to. To force the ping to go through the tun1 interface we need to force the solution we've found is to change the routing table. The problem with this solution is that we need to know where we want to send our ping and to edit the table before sending pings. If we want to ping cloudflare DNS : _1.1.1.1_ we need to enter the following command.

```
sudo ip route add 1.1.1.1/32 dev tun1
```

Now we are ready to start

```
sudo ./client
```

### On the server side :

We also need to start the server program on the server. We connect to the server via an SSH connection. Then we start the program :

```
sudo ./server
```

### Conclusion :

To see the incoming and outcoming packets, we can capture using tshark/Wireshark

```
tshark -w capture.pcap
```
