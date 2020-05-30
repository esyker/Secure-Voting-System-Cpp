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

int numb_candidates;
int num_voters;
int numb_trustees;



//cria uma string com FILE_NAME_SIZE letras aleatorias
void randomFileName(char* filename_)
{
	int i = 0;
	for(i = 0; i < FILE_NAME_SIZE-1; i++)
	{
		filename_[i] = rand()%26+97;
	}
	filename_[FILE_NAME_SIZE-1] = '\0';
}

//converte um inteiro em decimal numa string em hexadecimal
const char* decimalToHexadecimal(int decimal_value)
{
  std::stringstream ss;
  ss<< std::hex << decimal_value; // int decimal_value
  std::string res ( ss.str() );
  return res.c_str();
}

//pede ao utilizador o número de trustees, votantes e candidatos
void initData()
{
	char str[STRING_SIZE];
	int tmp=0;
	int verify=0;
	do
	{
		printf("\nNúmero de candidatos: ");

		fgets(str, STRING_SIZE, stdin);
		//converter a string para uma variável do tipo inteiro
		verify = sscanf(str,"%d", &tmp);

		if (tmp <= 0)
		{
			printf("Valor inválido\n");
			verify = 0;
		}
	}
	while (verify != 1);

	numb_candidates=tmp;
	tmp=0;

	do
	{
		printf("\nNúmero de voters: ");

		fgets(str, STRING_SIZE, stdin);
		//converter a string para uma variável do tipo inteiro
		verify = sscanf(str,"%d", &tmp);

		if (tmp <= 0)
		{
			verify=0;
			printf("Valor inválido\n");
		}
	}
	while (verify != 1);

	num_voters=tmp;
	tmp=0;

	do
	{
		printf("\nNúmero de trustees: ");

		fgets(str, STRING_SIZE, stdin);
		//converter a string para uma variável do tipo inteiro
		verify = sscanf(str,"%d", &tmp);

		if (tmp < 2)
		{
			verify=0;
			printf("Valor inválido\n");
		}
	}
	while (verify != 1);

	numb_trustees=tmp;
}

int main()
{
	char str[STRING_SIZE];
	FILE * fptr;
	FILE* fp;
	char filename[FILE_NAME_SIZE];
	std::string votes_weights;

	srand(time(NULL));

	//remover diretorias da votação anterior
	system("sudo rm -r Admin");
	system("sudo rm -r Voters");
	system("sudo rm -r Tally");
	system("sudo rm -r Trustees");
	system("sudo rm -r Ballot");
	system("sudo rm -r Counter");

	initData();

	system("mkdir Admin");
	chdir("Admin");
	system("mkdir ../Ballot");
	system("mkdir ../Counter");
	system("mkdir ../Trustees");
	system("mkdir ../Tally");
	system("mkdir ../Voters");


	//generate root CA private key
	system("sudo openssl genrsa -out root-ca.key 2048");

	//generate root CA certificate
	system("sudo openssl req -new -x509 -days 3650 -key root-ca.key -out root-ca.crt -subj '/CN=CA14/O=CSC-14/C=PT'");

	//install root CA certificate in Tally
	system("sudo cp root-ca.crt ../Tally");

	int i;

	for(i = 0; i < num_voters; i++)
	{
		//generate public and private key for every voter
		sprintf(str, "sudo openssl genrsa -out voter%d.key 1024", i+1);
		system(str);

		//generate certificate request for every voter
		sprintf(str, "sudo openssl req -new -key voter%d.key -out voter%d.csr -subj '/CN=CA14/O=voter%d/C=PT'", i+1, i+1, i+1);
		system(str);

		//sign certificate request to produce certificate
		sprintf(str, "sudo openssl x509 -req -in voter%d.csr -out voter%d.crt -sha1 -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -days 3650", i+1, i+1);
		system(str);

		//sign voter private key with CA private key
		sprintf(str, "sudo openssl dgst -sha1 -sign root-ca.key -out voter%d.key.sha1 voter%d.key", i+1, i+1);
		system(str);

		//remove certificate request
		sprintf(str, "sudo rm voter%d.csr", i+1);
		system(str);


	}


	//generate election key
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = POLY_MODULUS_DEGREE;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PLAIN_MODULUS);
	auto context = SEALContext::Create(parms);
	KeyGenerator keygen(context);
	PublicKey election_public_key = keygen.public_key();
	SecretKey election_secret_key = keygen.secret_key();
	//save election public key
	std::ofstream ofs("election_public_key", std::ios_base::binary);
	election_public_key.save(ofs);
	//save election secret key
	std::ofstream ofs2("election_secret_key", std::ios_base::binary);
	election_secret_key.save(ofs2);


	//writes number of voters in file
	fp = fopen("N_voter.txt", "w");
	if (fp == NULL)
	{
		printf("ERROR\n");
	  return -1;
	}
	fprintf (fp, "%d\n",num_voters);
	fclose(fp);
	//sign file with root certificate
	system("sudo openssl dgst -sha1 -sign root-ca.key -out N_voter.txt.sha1 N_voter.txt");

	//writes number of candidates in file
	fp = fopen("N_candi.txt", "w");
	if (fp == NULL)
	{
		printf("ERROR\n");
	  return -1;
	}
	fprintf (fp, "%d\n", numb_candidates);
	fclose(fp);

	//sign file with root CA
	system("sudo openssl dgst -sha1 -sign root-ca.key -out N_candi.txt.sha1 N_candi.txt");

	//writes number of trustees in file
	fp = fopen("N_trustees.txt", "w");
	if (fp == NULL)
	{
		printf("ERROR\n");
	  return -1;
	}
	fprintf (fp, "%d\n", numb_trustees);
	fclose(fp);

	//sign file with root CA
	system("sudo openssl dgst -sha1 -sign root-ca.key -out N_trustees.txt.sha1 N_trustees.txt");


	//sign election public key with CA private key
	system("sudo openssl dgst -sha1 -sign root-ca.key -out election_public_key.sha1 election_public_key");


	for(i = 0; i < num_voters; i++)
	{
		//make a directory for each voter
		sprintf(str, "mkdir ../Voters/voter%d", i+1);
		system(str);

		//install root CA certificate on voter app
		system("sudo cp root-ca.crt ../Voters");

		//install election public key on voter app
		sprintf(str, "sudo cp election_public_key ../Voters/voter%d", i+1);
		system(str);
		sprintf(str, "sudo cp election_public_key.sha1 ../Voters/voter%d", i+1);
		system(str);

		//install voter private key on voter app
		sprintf(str, "sudo cp voter%d.key.sha1 ../Voters/voter%d", i+1, i+1);
		system(str);
		sprintf(str, "sudo cp voter%d.key ../Voters/voter%d", i+1, i+1);
		system(str);
		//install voter certificate on voter app
		sprintf(str, "sudo cp voter%d.crt ../Voters/voter%d", i+1, i+1);
		system(str);


		//remove files from admin
		sprintf(str, "sudo rm voter%d.key.sha1", i+1);
		system(str);
		sprintf(str, "sudo rm voter%d.key", i+1);
		system(str);
		sprintf(str, "sudo rm voter%d.crt", i+1);
		system(str);
	}

	//split election secret key using Shamir's secret sharing
	sprintf(str, "cat election_secret_key | ~/.cargo/bin/secret-share-split -n %d -t %d >shares.txt", numb_trustees, numb_trustees);
	system(str);


	//split shares by trustees
	fptr=fopen("shares.txt", "r");
	char* line = (char*)malloc(sizeof(char)*LINE_SIZE); //each line corresponds to a share
	for(i = 0 ; i < numb_trustees; i++)
	{
		sprintf(str, "mkdir ../Trustees/trustee%d", i+1);
		system(str);
		fgets(line, LINE_SIZE, fptr);
		sprintf(str, "../Trustees/trustee%d/shares%d.txt", i+1, i+1);
		fp = fopen(str, "w");
		fprintf(fp, "%s", line); //write each share in a file in the trustee's directory
		fclose(fp);
	}
	free(line);
	fclose(fptr);

	//delete secret key
	system("rm shares.txt");
	system("rm election_secret_key");

	//sends number of candidats to voters
	system("sudo cp N_candi.txt ../Voters");
	system("sudo cp N_candi.txt.sha1 ../Voters");
	//sends number of voters to voters
	system("sudo cp N_voter.txt ../Voters");
	system("sudo cp N_voter.txt.sha1 ../Voters");


	Encryptor encryptor(context,election_public_key);

	//generate weights for Voters
	fptr = fopen("weights.txt", "w");
	for(i=0;i<num_voters;i++)
	{
		randomFileName(filename);
		std::ofstream weight_stream(filename, std::ios_base::binary);
		int tmp=0;
		int verify=0;
		//ask for weight for each voter
		do
		{
			printf("\nPeso para voter%d: ", i+1);

			fgets(str, STRING_SIZE, stdin);
			//converter a string para uma variável do tipo inteiro
			verify = sscanf(str,"%d", &tmp);

			if (tmp < 0)
			{
				verify=0;
				printf("Valor inválido\n");
			}
		}
		while (verify != 1);
		int weight = tmp;
		//encrypt weight using SEAL
		Plaintext weight_plain(decimalToHexadecimal(weight));
		Ciphertext weight_encrypted;
		encryptor.encrypt(weight_plain,weight_encrypted);
		weight_encrypted.save(weight_stream);
		fprintf(fptr, "voter%d: %s\n", i+1, filename);

		//copy individual weights to tally
		sprintf(str, "cp %s ../Tally", filename);
		system(str);
		sprintf(str, "rm %s", filename);
		system(str);

	}
	fclose(fptr);

	//send weights file to tally
	system("cp weights.txt ../Tally");
	system("rm weights.txt");
	//sends number of candidates to tally
	system("sudo cp N_candi.txt ../Tally");
	system("sudo cp N_candi.txt.sha1 ../Tally");
	//sends number of voters to tally
	system("sudo cp N_voter.txt ../Tally");
	system("sudo cp N_voter.txt.sha1 ../Tally");

	system("sudo cp election_public_key ../Tally");



	//sends number of candidates to counter
	system("sudo cp N_candi.txt ../Counter");
	system("sudo cp N_candi.txt.sha1 ../Counter");
	//sends number of voters to counter
	system("sudo cp N_voter.txt ../Counter");
	system("sudo cp N_voter.txt.sha1 ../Counter");
	//sends number of Trustees to counter
	system("sudo cp N_trustees.txt ../Counter");
	system("sudo cp N_trustees.txt.sha1 ../Counter");

	//install root CA certificate in counter
	system("sudo cp root-ca.crt ../Counter");


}
