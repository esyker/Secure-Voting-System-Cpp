#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <time.h>
#include "seal/seal.h"
#include "defs.h"


using namespace std;
using namespace seal;

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


//recebe uma linha de votação (ex: voter1;1234567;Candidate1:abcdefghij;...;),
//contrói uma string contendo as hashes dos ficheiros (ex: voter1;1234567;Candidate1:<hash(abcdefghij)>;...;),
//e assina essa linha. A assinatura é guardada num ficheiro e o nome desse ficheiro é anexado à linha original
//(ex: voter1;1234567;Candidate1:abcdefghij;...;Signature:qwertyuiop;)
//retorna 1 em caso de sucesso e 0 caso contrário
int sign_line(char* line)
{
	char str[STRING_SIZE];
	int i = 0;
  int timestamp;
  int candidate;
  FILE* fptr;
  int voterID;
  int span;
  char file[STRING_SIZE];
  char hash[STRING_SIZE];
  char file_signature[FILE_NAME_SIZE];
	char ostr[STRING_SIZE*5]; //string que irá ser assinada

  if(sscanf(line, "voter%d;%d;%n", &voterID, &timestamp, &span) != 2)
    return 0;
  i = i+span;
	sprintf(ostr, "voter%d;%d;",voterID, timestamp);
	while(1)
	{
    span = 0;
		if(sscanf(line+i, "Candidate%d:%n%[^;]s;", &candidate, &span, file) == 2)
    {
      i = i+span + strlen(file)+1;
      //calculate hash for file
			sprintf(str, "(openssl sha1 %s) > %s.sha1", file, file);
      system(str);
      sprintf(str, "%s.sha1", file);
      fptr = fopen(str, "r");
      sprintf(str, "SHA1(%s)= %%s", file);
      fscanf(fptr, str, hash); //get the hash
      fclose(fptr);
			sprintf(str, "rm %s.sha1", file);
      system(str);
      sprintf(str, "Candidate%d:%s;", candidate, hash);
			strcat(ostr, str); //write hash to output sting
			sprintf(str, "sudo rm %s", file);
			system(str);
    }
    else
    {
      break;
    }
	}

	randomFileName(file_signature);

  fptr = fopen("line","w");
	fprintf(fptr, "%s", ostr);
  fclose(fptr);
  sprintf(str, "sudo openssl dgst -sha1 -sign voter%d.key -out %s line", voterID, file_signature); //sign file containing output string with voter private key
  system(str);

  strcat(line, "Signature:");
  strcat(line, file_signature);
  strcat(line, ";"); //append signature to original line

	sprintf(str, "sudo cp %s ../../Ballot", file_signature);
	system(str); //copy file containing the signature to Ballot box

	sprintf(str, "sudo rm %s", file_signature);
	system(str);

  system("rm line");
  return 1;

}

//retorna um número existente no ficheiro "ficheiro", se se verificar que este está assinado pelo root CA. retorna -1 caso contrário
int get_nFicheiro(char* ficheiro)
{
	int n=0;
	char str[STRING_SIZE] = {0};
	FILE *fp;

	//verifica a assinatura (o output do comando é passado para o ficheiro "Result")
	sprintf(str,"sudo su -c 'openssl dgst -sha1 -verify  <(openssl x509 -in root-ca.crt -pubkey -noout) -signature %s.txt.sha1 %s.txt' > Result", ficheiro, ficheiro);
	system(str);

	fp = fopen("Result", "r");
	if (fp == NULL)
	{
		printf("ERROR\n");
	  return -1;
	}
	fgets(str, STRING_SIZE, fp);
	if(strcmp(str, "Verified OK\n")!= 0)
	{
		fclose(fp);
		printf("ERROR\n");
		return -1;
	}
	fclose(fp);
	system("rm Result");
	sprintf(str,"%s.txt", ficheiro);
	fp = fopen(str, "r");
	if (fp == NULL)
	{
  	printf("ERROR\n");
	  return -1;
	}

	fgets(str, STRING_SIZE, fp);
	sscanf(str, "%d", &n);
	fclose(fp);
	printf("%s: VERIFIED OK\n", ficheiro);
	return n;
}

int main()
{
	char str[STRING_SIZE];
	char str1[STRING_SIZE] = {0};
	int verify=0 , done=0;
	int n_candi=0, n_voter=0;
	int voterID = 0;
	int *votes;
	int i=0, j=0;
	int candi_votes=0;
	FILE *fptr;
	srand(time(NULL));
	char filename[FILE_NAME_SIZE];

	chdir("Voters");

	char tmp[]="N_voter";
	n_voter=get_nFicheiro(tmp); //adquirir número de votantes
	if (n_voter==-1)
	{
		printf("Não foi possível adquirir o número de votantes\n");
		exit (0);
	}

	//perguntar número ao votante
	do
	{
			printf("\nEscreva o seu número de votante: ");

			fgets(str1, STRING_SIZE, stdin);
			//converter a string para uma variável do tipo inteiro
			verify = sscanf(str1,"%d", &voterID);

			if (voterID > n_voter || voterID < 0)
			{
				printf("Número de votante inválido\n");
				verify=0;
			}
	}
	while (verify != 1);


	char tmp1[]="N_candi";
	n_candi=get_nFicheiro(tmp1); //adquirir numero de candidatos
	if (n_candi==-1)
	{
		printf("Não foi possível adquirir o número de candidatos\n");
		exit (0);
	}

	sprintf(str,"voter%d",voterID);
	chdir(str);
	votes = (int*)calloc(n_candi,sizeof(int));

	//verify voter certificate
	sprintf(str, "sudo openssl verify -CAfile ../root-ca.crt voter%d.crt", voterID);
	system(str);

	//verify voter private key
	sprintf(str, "sudo su -c 'openssl dgst -sha1 -verify  <(openssl x509 -in ../root-ca.crt -pubkey -noout) -signature voter%d.key.sha1 voter%d.key'", voterID, voterID);
	system(str);

	//verify election public key
	system("sudo su -c 'openssl dgst -sha1 -verify  <(openssl x509 -in ../root-ca.crt -pubkey -noout) -signature election_public_key.sha1 election_public_key'");

	//load election public key from file
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = POLY_MODULUS_DEGREE;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PLAIN_MODULUS);
	auto context = SEALContext::Create(parms);

	std::ifstream ifs ("election_public_key", std::ios_base::binary);

	PublicKey election_public_key;
	election_public_key.load(context, ifs); //load election public key

	Encryptor encryptor(context, election_public_key);


	int vote=0;
	int n_votes=0;
	//pedir votos ao votante
	while(!done)
	{
		do
    {
        printf("\nEscreva o número do candidato a votar ou \"0\" para sair: ");

        fgets(str1, STRING_SIZE, stdin);

        //converter a string para uma variável do tipo inteiro
        verify = sscanf(str1,"%d", &vote);

				if (vote == 0)
				{
					done=1;
				}
    }
    while (verify != 1);

		if (vote !=0)
		{
			printf("Votou no candidato %d\n", vote);
			votes[n_votes]=vote;
			n_votes++;
			if(n_votes==n_candi)
			{
				done=1;
			}
		}
	}

	//contruir a linha de voto
	std::string str_voto;
	sprintf(str, "voter%d;%ld;", voterID, time(NULL));
	str_voto.append(str);
	//contar votos em cada candidato
	for (i=1;i<=n_candi; i++)
	{
		candi_votes=0;
		for (j=0; j < n_candi; j++)
		{
			if (votes[j]==i)
			{
				candi_votes++;
				votes[j]=0;
			}
		}
		randomFileName(filename);
		std::ofstream vote_stream(filename, std::ios_base::binary);
		Plaintext vote_plain(decimalToHexadecimal(candi_votes)); //encriptar numero de votos em cada candidato
		Ciphertext vote_encrypted=Ciphertext(context);
		encryptor.encrypt(vote_plain,vote_encrypted);
		vote_encrypted.save(vote_stream); //guardar numero de votos encriptado num ficheiro
		sprintf(str, "Candidate%d:%s;", i, filename);
		str_voto.append(str);
		sprintf(str, "sudo cp %s ../../Ballot", filename);
		system(str);
	}

	//contagem do numero de votos em candidatos que não existem
	for (i=0;i < n_candi; i++)
	{
		candi_votes=0;
		if (votes[i] !=0)
		{
			vote=votes[i];
			candi_votes++;
			votes[i]=0;
			for (j=i; j < n_candi; j++)
			{
				if (votes[j] == vote)
				{
					candi_votes++;
					votes[j]=0;
				}
			}
			randomFileName(filename);
			std::ofstream vote_stream(filename, std::ios_base::binary);
			Plaintext vote_plain(decimalToHexadecimal(candi_votes));
			Ciphertext vote_encrypted;
			encryptor.encrypt(vote_plain,vote_encrypted);
			vote_encrypted.save(vote_stream);
			sprintf(str, "Candidate%d:%s;", vote, filename);
			str_voto.append(str);
			sprintf(str, "sudo cp %s ../../Ballot", filename);
			system(str);
		}
	}

	//assinar a linha
	if (sign_line(const_cast<char*>(str_voto.c_str())) == 0)
	{
		printf("ERROR\n");
	  return -1;
	}

	//juntar à urna a linha de voto assinada
	fptr = fopen("../../Ballot/Urna.txt", "a");
	fprintf(fptr, "%s\n", const_cast<char*>(str_voto.c_str()));
	fclose(fptr);

	//copiar certificado do voter para a urna
	sprintf(str, "sudo cp voter%d.crt ../../Ballot", voterID);
	system(str);

	//free memory
	free(votes);

}
