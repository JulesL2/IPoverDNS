#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#include "fragmentation.h"

//prend en entrée du texte T, coupe T en plusieurs paquets de taille inférieure à 46 + 2 octets
//je suppose que *paquets soit de la forme paquets[nbDePaquets][48]
int decouper(char *T, char (*paquets)[][48])
{

	int N = 48 - 3;
	const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	int nbDePaquets = strlen(T)/N + 1;

	for (int i = 0; i < nbDePaquets; i++)
	{

		struct fragmentationHeader *header;
		header = (struct fragmentationHeader *)&(*paquets)[i];
		header->fragmentMax = base64chars[nbDePaquets - 1];
		header->fragmentId = (unsigned char)base64chars[i];

		if (strlen(T + i * N) >= N)
		{
			memcpy((*paquets)[i] + 2, T + i * N, N);
			*((*paquets)[i] + N + 2) = '\0';
		}
		else
		{
			memcpy((*paquets)[i] + 2, T + i * N, strlen(T + i * N));
			int j = strlen(T + i * N);
			while(j <= 46){
				*((*paquets)[i] + 2 + j) = '\0';
				j++;
			}
		}

		//Ceci sert à tester la fragmentation
		/*
		struct fragmentationHeader *test = (struct fragmentationHeader *)&(*paquets)[i];
		printf("fragment Id: %c\n", test->fragmentId);
		printf("fragment Max : %c\n", test->fragmentMax);
		printf("fragment Max nb : %d\n", nbFragmentMax(&(*paquets)[i]));
		printf("Payload: %s\n\n", (*paquets)[i] + 2);
		*/
	}
	return nbDePaquets;
}

int rassembler(char (*paquets)[][48], char* T, int nbFragments)
{

	const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	int i;

	//Ceci sert à tester la fragmentation
	/*
	printf("nbFragments = %d\n", nbFragments);
	knuthShuffle(&paquets, nbFragments);
	for (int j = 0; j < nbFragments; j++){
		struct fragmentationHeader *test = (struct fragmentationHeader *)&paquets[j];
                printf("fragment Id: %c\n", test->fragmentId);
                printf("fragment Max : %c\n", test->fragmentMax);
                printf("fragment Max nb : %d\n", nbFragmentMax(&paquets[j]));
                printf("Payload: %s\n\n", paquets[j] + 2);
	}
	*/

	for(int k = 0; k < nbFragments; k++) {

		i=0;
		struct fragmentationHeader *header = (struct fragmentationHeader *)&(*paquets)[k];
		while(strncmp(&base64chars[i], &header->fragmentId, 1) != 0){
			i++;
		}
		memcpy(T + 45*i, (*paquets)[k]+2, 45);

	}


	for(int k = 0; k < nbFragments; k++) {
		struct fragmentationHeader *header = (struct fragmentationHeader *)&(*paquets)[k];
		if (strncmp(&header->fragmentId, &header->fragmentMax, 1) == 0){
			memcpy(T + 45*(nbFragments - 1), (*paquets)[k] + 2, 46);
			break;
		}
	}

	return 0;
}

int nbFragmentMax(char (*paquet)[48]){

	const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int i = 0;
	struct fragmentationHeader *header = (struct fragmentationHeader *)paquet;
        while(strncmp(&base64chars[i], &header->fragmentMax, 1) != 0){
                i++;
        }
	return i;

}


//inspiré de https://www.rosettacode.org/wiki/Knuth_shuffle#C
//l'utilité étant simplement de bien tester les fonctions précédentes
int knuthShuffle(char (**paquets)[48], int nbFragments){

	int j;
	char paquetTmp[48];
	srand( time(NULL));

	for(int i = nbFragments; i > 1; i--){

		j = rand() % i;
		//printf("Random nb is: %d\n", j);

		if(j != i-1){
			strncpy(paquetTmp, (*paquets)[j], 48);
			strncpy((*paquets)[j], (*paquets)[i-1],48);
			strncpy((*paquets)[i-1], paquetTmp, 48);
		}

	}

	return 0;
}
