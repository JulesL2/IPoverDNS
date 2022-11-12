#ifndef FRAGMENTATION_H_
#define FRAGMENTATION_H_

struct fragmentationHeader{

	//unsigned char moreFragmentation :1;
	//unsigned char packetId :7;
	unsigned char fragmentMax;
	unsigned char fragmentId;

};

int rassembler(char (*paquets)[][48], char* T, int nbFragments);
int decouper(char *T, char (*paquets)[][48]);
int nbFragmentMax(char (*paquet)[48]);
int knuthShuffle(char (**paquets)[48], int nbFragments);
#endif
