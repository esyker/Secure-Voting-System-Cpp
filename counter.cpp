#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <time.h>
#include "seal/seal.h"
#include "defs.h"


using namespace std;
using namespace seal;

int num_candidates;
int num_voters;
int numb_trustees;

char filename[FILE_NAME_SIZE];

/************************************************************************************************
Função para converter um número em formato de string em hexadecimal para inteiro em decimal
*************************************************************************************************/

int hexadecimalToDecimal(const char* hexVal)
{
	long long decimal;
	int i = 0, val, len;

	decimal = 0;

	/* Find the length of total number of hex digit */
	len = strlen(hexVal);
	len--;

		for(i=0; hexVal[i]!='\0'; i++)
		{

				/* Find the decimal representation of hex[i] */
				if(hexVal[i]>='0' && hexVal[i]<='9')
				{
						val = hexVal[i] - 48;
				}
				else if(hexVal[i]>='a' && hexVal[i]<='f')
				{
						val = hexVal[i] - 97 + 10;
				}
				else if(hexVal[i]>='A' && hexVal[i]<='F')
				{
						val = hexVal[i] - 65 + 10;
				}

				decimal += val * pow(16, len);
				len--;
		}
	return decimal;
}


/********************************************************************************************
			.Função para verficar se um ficheiro está assinado pelo admin (root-ca)
			.No caso do counter, esta função só é utilizada para verificar se o ficheiro onde estão
			os parâmetros da eleição está assinado pelo root, isto é, se foi emitido pelo admin
*********************************************************************************************/

int Verify_Signature(const char* ficheiro)
{
	char str[STRING_SIZE] = {0};
	FILE *fp;
	sprintf(str,"sudo su -c 'openssl dgst -sha1 -verify  <(openssl x509 -in root-ca.crt -pubkey -noout) -signature %s.txt.sha1 %s.txt' > Result", ficheiro, ficheiro);
	system(str);

	fp = fopen("Result", "r");
	if (fp == NULL)
	{
		printf("ERROR verifying signature!\n");
	  return -1;
	}
	fgets(str,STRING_SIZE, fp);
	printf("%s", str);
	if(strcmp(str, "Verified OK\n")!= 0)
	{
		fclose(fp);
		printf("ERROR verifying signature!\n");
		return -1;
	}
	fclose(fp);
	system("rm Result");
	return 1;
}

int main()
{

	/*******************************************************
					Inicializar parâmetros de encriptação
	********************************************************/
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = POLY_MODULUS_DEGREE;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PLAIN_MODULUS);
	auto context = SEALContext::Create(parms);

	/******************************************************
							Variáveis auxiliares
	******************************************************/
	FILE* fptr;
	FILE* fp;
	chdir("Counter");
	char* line;
	int i;
	char str[STRING_SIZE];

	/******************************************************
					Ler os parâmetros da eleição
	********************************************************/

	//ler o número de Candidatos
	fptr=fopen("N_candi.txt","r");
	fscanf(fptr,"%d",&num_candidates);
	fclose(fptr);
	if(!Verify_Signature("N_candi"))
		exit(-1);
	//ler o número de Votantes
	fptr=fopen("N_voter.txt","r");
	fscanf(fptr,"%d",&num_voters);
	fclose(fptr);
	if(!Verify_Signature("N_voter"))
		exit(-1);
	//ler o número de Trustees
	fptr=fopen("N_trustees.txt","r");
	fscanf(fptr,"%d",&numb_trustees);
	fclose(fptr);
	if(!Verify_Signature("N_trustees"))
		exit(-1);

	/***************************************************************************
				Reconstruir  a election_private_key usando Shamir Secret Sharing
	****************************************************************************/
	fptr=fopen("shares_reconstructed.txt", "w");
	line = (char*)malloc(sizeof(char)*LINE_SIZE);

	for(i = 0 ; i < numb_trustees; i++)
	{
		sprintf(str, "../Trustees/trustee%d/shares%d.txt", i+1, i+1);
		fp = fopen(str, "r");
		fgets(line, LINE_SIZE, fp);
		fprintf(fptr, "%s", line);
		fclose(fp);
	}

	fclose(fptr);

	//reconstruir a chave usando a biblioteca do Shamir secret Sharing
	sprintf(str, "head -n %d shares_reconstructed.txt | ~/.cargo/bin/secret-share-combine > recombined_secret_key", numb_trustees);
	system(str);

	//Ler a chave reconstruída do ficheiro
	std::ifstream recombined_stream("recombined_secret_key");
	SecretKey recombined_secret_key;
	recombined_secret_key.load(context, recombined_stream);

	/*************************************************************
									Desencriptar os checksums
	**************************************************************/

	Decryptor decryptor(context, recombined_secret_key);

	fptr = fopen("checksum_accumulator.txt", "r");
	int invalid = 0;
	printf("\nChecksums:\n");

	for(i=0;i<num_voters;i++)
	{
		int n;
		int checksum;
		fgets(str, STRING_SIZE, fptr);
		sscanf(str, "voter%d:%s", &n, filename);
		Ciphertext checksum_encrypted;
		Plaintext checksum_plain;
		std::ifstream checksum_stream(filename);
		checksum_encrypted.load(context, checksum_stream);
		decryptor.decrypt(checksum_encrypted, checksum_plain);
		checksum=hexadecimalToDecimal(checksum_plain.to_string().c_str());
		printf("Voter %d checksum: %d\n",i+1, checksum);
		if(checksum != num_candidates)
		{
			invalid = 1;
		}

	}
	fclose(fptr);


	if(invalid)
	{
		printf("\nChecksums incorretos! Resultados das Eleições inválidos!\n\n");
	}
	else
		printf("\nChecksums verificados! Resultados das Eleições válidos!\n\n");


	/************************************************************************
							Desencriptar o resultado das eleições
	*************************************************************************/
	Ciphertext count_encrypted;
	Plaintext count_plain;
	int vote_count;

	std::ifstream count_stream;
	for(i=1;i<=num_candidates;i++)
	{
		sprintf(str,"Candidate%d",i);
		count_stream.open(str);
		count_encrypted.load(context,count_stream);
		count_stream.close();
		decryptor.decrypt(count_encrypted,count_plain);
		vote_count=hexadecimalToDecimal(count_plain.to_string().c_str());
		printf("Candidate%d:%d\n",i, vote_count);
	}

	/*****************************************************************
	Libertar a memória das estruturas de dados alocadas dinamicamente
	******************************************************************/
	free(line);
}
