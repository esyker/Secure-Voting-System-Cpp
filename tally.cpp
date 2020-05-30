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

//cria uma estrutura para guardar cada voto
typedef struct vote
{
    long int time_stamp; //guardar o tempo em que o voto foi realizado
    long int numb; // número do votante
		char** files_names; //nomes dos ficheiros com o voto em cada candidato
    char weight_file[FILE_NAME_SIZE]; // nome do ficheiro com o peso do voto
} vote;

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

//verifica a assinatura de uma linha na urna usando o openssl
int verify_line_signature(char* line)
{
	int i = 0;
  int timestamp;
  int candidate;
  FILE* fptr;
  int voterID;
  int span;
  char file[STRING_SIZE];
  char hash[STRING_SIZE];
	char str[STRING_SIZE];
  char str1[STRING_SIZE];
  char file_signature[STRING_SIZE];
	char ostr[STRING_SIZE*5];


  if(sscanf(line, "voter%d;%d;%n", &voterID, &timestamp, &span) != 2)
    return 0;
  i = i+span;
	sprintf(ostr, "voter%d;%d;",voterID, timestamp);

  //verifica se o certificado do voter foi assinado pelo root (usando o root-ca.crt)
  sprintf(str, "(sudo openssl verify -CAfile root-ca.crt ../Ballot/voter%d.crt) > Result", voterID);
	system(str);

  fptr = fopen("Result", "r");
	if (fptr == NULL)
	{
		printf("ERROR\n");
	  return 0;
	}
	fgets(str, STRING_SIZE, fptr);

  sprintf(str1, "../Ballot/voter%d.crt: OK\n", voterID);
	if(strcmp(str, str1)!= 0)
	{
    printf("ERROR\n");
		fclose(fptr);
    system("rm Result");
		return 0;
	}
  fclose(fptr);
  system("rm Result");

  //verifica se o nome do certificado é o do voter
  sprintf(str, "(sudo openssl x509 -noout -subject -in ../Ballot/voter%d.crt) > Result", voterID);
	system(str);

  fptr = fopen("Result", "r");
	if (fptr == NULL)
	{
		printf("ERROR\n");
	  return 0;
	}
	fgets(str, STRING_SIZE, fptr);

  sprintf(str1, "subject=CN = CA14, O = voter%d, C = PT\n", voterID);
	if(strcmp(str, str1)!= 0)
	{
    printf("ERROR\n");
		fclose(fptr);
    system("rm Result");
		return 0;
	}
  fclose(fptr);
  system("rm Result");

  //reconstrói a string com as hashes dos ficheiros (ex: voter1;1234567;Candidate1:<hash(abcdefghij)>;...;)
  //o ficheiro foi assinado com as hashes
  //deste modo, está assegurado que o ficheiro não foi corrompido
	while(1)
	{
    span = 0;
		if(sscanf(line+i, "Candidate%d:%n%[^;]s;", &candidate, &span, file) == 2)
    {
      i = i+span + strlen(file)+1;
      //calculate hash for file
      sprintf(str, "(openssl sha1 ../Ballot/%s) > %s.sha1", file, file);
      system(str);
      sprintf(str, "%s.sha1", file);
      fptr = fopen(str, "r");
      sprintf(str, "SHA1(../Ballot/%s)= %%s", file);
      fscanf(fptr, str, hash);
      fclose(fptr);
      sprintf(str, "Candidate%d:%s;", candidate, hash);
			strcat(ostr, str);
    }
    else
    {
      if(sscanf(line+i, "Signature:%[^;]s;", file_signature) == 1)
        break;
      else
        return 0;
    }
	}

	fptr = fopen("line_","w");
	fprintf(fptr, "%s", ostr);
  fclose(fptr);

  //verifica a assinatura da linha
	sprintf(str,"sudo su -c 'openssl dgst -sha1 -verify  <(openssl x509 -in ../Ballot/voter%d.crt -pubkey -noout) -signature ../Ballot/%s line_' > Result", voterID, file_signature);
	system(str);

	fptr = fopen("Result", "r");
	if (fptr == NULL)
	{
		printf("ERROR\n");
	  return 0;
	}
	fgets(str, STRING_SIZE, fptr);
	if(strcmp(str, "Verified OK\n")!= 0)
	{
		fclose(fptr);
		return 0;
	}
	fclose(fptr);

	system("rm Result");
  system("rm line_");
	printf("Voter %d: VERIFIED OK\n", voterID);
  return 1;
}

//retorna um número existente no ficheiro "ficheiro", se se verificar que este está assinado pelo root CA. retorna -1 caso contrário
//esta função é usada exclusivamente para ler o número de voters e candidates no início do programa
// a função lê um número do ficheiro e verifica se o mesmo é pertencente ao admin, isto é, se está assinado pelo root-ca
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
	int numb_voters; //número de votantes
	int numb_candidates; //número de candidatos
	vote* voter; //vetor com os votos

  /*Variáveis auxiliares*/
  vote voter_aux;
	char aux_char;
  char aux_str[30];
	char line [STRING_SIZE];
  int aux_int;
	int numb_candidate;
  std::ifstream aux_stream;
  FILE* fptr;

  //inicializar a semente, para gerar nomes de ficheiros aleatórios
  srand(time(NULL));

  chdir("Tally");

  //Ler do ficheiro N_voter o número de votos e verificar se está assinado pelo root-ca usando a função get_nFicheiro
  char tmp[]="N_voter";
  numb_voters=get_nFicheiro(tmp);
  if (numb_voters==-1)
  {
    printf("Não foi possível adquirir o número de votantes\n");
    exit (0);
  }

  //Ler do ficheiro N_candi o número de votos e verificar se está assinado pelo root-ca usando a função get_nFicheiro
  char tmp1[]="N_candi";
  numb_candidates=get_nFicheiro(tmp1);
  if (numb_candidates==-1)
  {
    printf("Não foi possível adquirir o número de candidatos\n");
    exit (0);
  }

  /****************************************************************************
      .Inicialização de um vetor voter da estrutura vote
      .Este vetor guarda apenas os votos válidos, a patir da estrutura auxiliar
  *****************************************************************************/

	voter=(vote*)malloc(numb_voters*sizeof(vote));
	for(int i=0;i<numb_voters;i++)
	{
    voter[i].time_stamp = 0;
		voter[i].files_names=(char**)malloc(numb_candidates*sizeof(char*));
		for(int j=0;j<numb_candidates;j++)
		{
			voter[i].files_names[j]=(char*)calloc(FILE_NAME_SIZE,sizeof(char));
      if(voter[i].files_names[j]==NULL)
        printf("Error allocating memory;");
		}
    //inicializar a -1 o número do votante no voto
    // se o número continuar a -1 no final da votação, significa que o votante não votou
		voter[i].numb=-1;
	}

  /***********************************************************************************
    .Inicialização de uma estrutura auxiliar para ler o voto do ficheiro
    .O voto é guardado a partir desta estrutura, se no fim da leitura do mesmo
    se verificar que o mesmo é válido
  ***********************************************************************************/
  voter_aux.files_names=(char**)malloc(numb_candidates*sizeof(char*));
  for(int j=0;j<numb_candidates;j++)
  {
    voter_aux.files_names[j]=(char*)calloc(FILE_NAME_SIZE,sizeof(char));
    if(voter_aux.files_names[j]==NULL)
      printf("Error allocating memory;");
  }

  /*******************************************************************************************************
            Ler os votos do Ficheiro e verificar se estão assinados usando a função verify_line_signature
  *********************************************************************************************************/

  fptr=fopen("../Ballot/Urna.txt","r");
	int succes_conversion=0;
	aux_char=0;

	while(aux_char!=EOF)
	{
		succes_conversion=fscanf(fptr,"voter%ld;%ld;",&voter_aux.numb,&voter_aux.time_stamp);
		if(succes_conversion==2)
		{
			sprintf(line,"voter%ld;%ld;",voter_aux.numb,voter_aux.time_stamp);
			if(voter_aux.numb<1||voter_aux.numb>numb_voters)
			{
				aux_char=0;
			}
			else {
				while(1)
				{
					// ler uma string com tamanho 10 com o nome do ficheiro onde está o voto no candidato
					succes_conversion=fscanf(fptr,"Candidate%d:%10s;",&numb_candidate,aux_str);
					if(numb_candidate<1||numb_candidate>numb_candidates||succes_conversion != 2)
					{
						aux_char=0;
						break;
					}
					sprintf(line+strlen(line),"Candidate%d:%s;",numb_candidate,aux_str);
					strcpy(voter_aux.files_names[numb_candidate-1],aux_str);
				}
				succes_conversion=fscanf(fptr,"Signature:%10s;",aux_str);
				sprintf(line+strlen(line),"Signature:%s;",aux_str);

			}

			if(succes_conversion==EOF)
			{

				if(verify_line_signature(line) && voter_aux.time_stamp > voter[voter_aux.numb-1].time_stamp)
				{
          //guardar o voto
					voter[voter_aux.numb-1].numb=voter_aux.numb;
					voter[voter_aux.numb-1].time_stamp=voter_aux.time_stamp;

					for(int i =0;i<numb_candidates;i++)
					{
						strcpy(voter[voter_aux.numb-1].files_names[i],voter_aux.files_names[i]);
						memset(voter_aux.files_names[i],0,strlen(voter_aux.files_names[i]));
					}
				}
			}
			else
			{
				aux_char=getc(fptr);
				if(aux_char=='\n')
				{
          if(verify_line_signature(line) && voter_aux.time_stamp > voter[voter_aux.numb-1].time_stamp)
					{
            //guardar o voto
						voter[voter_aux.numb-1].numb=voter_aux.numb;
						voter[voter_aux.numb-1].time_stamp=voter_aux.time_stamp;
						for(int i =0;i<numb_candidates;i++)//save the vote
						{
							strcpy(voter[voter_aux.numb-1].files_names[i],voter_aux.files_names[i]);
							memset(voter_aux.files_names[i],0,strlen(voter_aux.files_names[i]));
						}
					}
				}
				else
				{
          //continuar para a próxima linha, já que esta é inválida
					while(aux_char!=EOF&&aux_char!='\n')
					{
						aux_char=getc(fptr);
					}
					if(aux_char==EOF)
						break;
				}
			}
		}
		else
		{
      //continuar para a próxima linha, já que esta é inválida
			aux_char=getc(fptr);
			while(aux_char!=EOF&&aux_char!='\n')
			{
				aux_char=getc(fptr);
			}
			if(aux_char==EOF)
				break;
		}
	}

	fclose(fptr);

  /********************************************************
          Imprimir no ecrã os votos válidos obtidos
  ***********************************************************/
  printf("\nVotes obtained:");
  for(int j=0;j<numb_voters;j++)
  {
    if(voter[j].numb!=-1)
    {
      printf("\nVoter%ld Time_stamp:%ld Files_Names-> ",voter[j].numb,voter[j].time_stamp);
      for(int i=0;i<numb_candidates;i++)
      {
        if(strlen(voter[j].files_names[i])!=0)
          printf(" Candidate%d:%s",i+1,voter[j].files_names[i]);
      }
      printf("\n");
    }
 }

  /*******************************************************************
        Inicializar os parâmetros de encriptação
  *******************************************************************/

	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = POLY_MODULUS_DEGREE;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PLAIN_MODULUS);
	auto context = SEALContext::Create(parms);

	/************************************************************************************************
        Ler a public_key, utilizada para inicializar as CipherTexts com a contagem dos votos a 0
  ************************************************************************************************/
	PublicKey election_public_key;
	aux_stream.open("election_public_key");
	election_public_key.load(context,aux_stream);
	aux_stream.close();

  /**************************************************************************************
        .Criar vetores de Ciphertext, o accumulator e o candidates_votes
        .o candidates_votes guarda em CipherText o número de votos em cada candidato
        . o accumulator guarda em CipherText o checksum de cada votante
  ***************************************************************************************/
	Encryptor encryptor(context,election_public_key);
	Plaintext intialize_to_zero(decimalToHexadecimal(0));
	Ciphertext* candidates_votes=(Ciphertext*)calloc(numb_candidates,sizeof(Ciphertext));
  Ciphertext* accumulator=(Ciphertext*)calloc(numb_voters,sizeof(Ciphertext));
	Ciphertext aux_ciphertext(context);
	Evaluator evaluator(context);

  //inicializar o accumulator a 0 para cada votante
  for(int i=0;i<numb_voters;i++)
  {
    accumulator[i]=Ciphertext(context);
    encryptor.encrypt(intialize_to_zero,accumulator[i]);
  }

  //inicializar a 0 o vetor dos candidatos (cada posição do vetor tem os votos em cada candidato)
	for(int i=0;i<numb_candidates;i++)
	{
		candidates_votes[i]=Ciphertext(context);
		encryptor.encrypt(intialize_to_zero,candidates_votes[i]);
	}

	encryptor.encrypt(intialize_to_zero,aux_ciphertext);

  /********************************************************************
            Ler o peso de cada votante do ficheiro weights.txt
  ********************************************************************/
  fptr=fopen("weights.txt","r");

  for(int i=0;i<numb_voters;i++)
  {

      fscanf(fptr,"voter%d: %s ",&aux_int,voter[i].weight_file);

  }
  fclose(fptr);

  /**********************************************************************
  .somar ao accumulator o número de votos ->   evaluator.add_inplace(accumulator[i],aux_ciphertext);
  -multiplicar pelo weight o número de votos ->  evaluator.multiply_inplace(aux_ciphertext,weight);
  .somar ao vetor dos votos em cada candidato o número de votos multiplicado pelo weight->
  evaluator.add_inplace(candidates_votes[j],aux_ciphertext);
  **********************************************************************/

 Ciphertext weight = Ciphertext(); //CipherText auxiliar para ir lendo o weight de cada votante dum ficheiro

	for(int i=0;i<numb_voters;i++)
	{
    aux_stream.open(voter[i].weight_file);
    weight.load(context,aux_stream); //ler o weight de cada votante para um CipherText de nome weight
    aux_stream.close();

    //ver se o votante votou, isto é, se o seu número está diferente de -1
		if(voter[i].numb!=-1)
		{
				for(int j=0;j<numb_candidates;j++)
				{
						//ver se o ficheiro do voto existe
							if(strlen(voter[i].files_names[j])!=0)
							{
								sprintf(aux_str,"../Ballot/%s",voter[i].files_names[j]);
								aux_stream.open(aux_str);
								aux_ciphertext.load(context,aux_stream);
                evaluator.add_inplace(accumulator[i],aux_ciphertext);//somar ao accumulator o número de votos
			          evaluator.multiply_inplace(aux_ciphertext,weight);//multiplicar pelo weight o número de votos
                //somar ao vetor dos votos em cada candidato o número de votos multiplicado pelo weight
								evaluator.add_inplace(candidates_votes[j],aux_ciphertext);
								aux_stream.close();
							}
							else//Erro a ler o ficheiro -> ficheiro eliminado -> eleições inválidas
							{
								printf("\nError reading voter file\n");
								exit(-1);
							}

				}
		}
	}

  /*************************************************************************************************************
	 .Guardar o checksum de cada candidato num ficheiro com um nome gerado aleatoriamente
   .Guardar no ficheiro checksum_accumulator.txt, em cada linha, o número de cada votante e o correspondente nome
   do ficheiro gerado aleatoriamente, onde está o seu checksum
  .o checksum de cada voter está guardado numa posição de um vetor de CipherText, accumulator
  ************************************************************************************************************/

  FILE* fptr_accumulator = fopen("checksum_accumulator.txt","w");
  std::ofstream save_accumulator;
  char command[STRING_SIZE];

  for(int i=0;i<numb_voters;i++)
  {
      randomFileName(aux_str);
      fprintf(fptr_accumulator,"voter%d:%s\n",i+1,aux_str);
      save_accumulator.open(aux_str,std::ios_base::binary);
      accumulator[i].save(save_accumulator);
      save_accumulator.close();
      sprintf(command,"sudo cp %s ../Counter",aux_str);
      system(command);
  }

	fclose(fptr_accumulator);

  system("sudo cp checksum_accumulator.txt ../Counter");

  /**************************************************************************
	.Guardar os votos em cada candidato num ficheiro correspondente
  .os votos foram somados e guardados num vetor de Ciphertext, candidates_votes
  *****************************************************************************/

	std::ofstream save_votes;
	for(int i=1;i<=numb_candidates;i++)
	{
		sprintf(aux_str,"Candidate%d",i);
		save_votes.open(aux_str,std::ios_base::binary);
		candidates_votes[i-1].save(save_votes);
		save_votes.close();
		sprintf(aux_str,"sudo cp Candidate%d ../Counter",i);
		system(aux_str);
	}

  /***************************************************************
  Libertar a memória de todas as estruturas alocadas dinamicamente
  ****************************************************************/

  for(int i=0;i<numb_voters;i++)
  {
    for(int j=0;j<numb_candidates;j++)
      free(voter[i].files_names[j]);

    free(voter[i].files_names);
  }
  free(voter);

  for(int j=0;j<numb_candidates;j++)
    free(voter_aux.files_names[j]);

  free(voter_aux.files_names);
  free(candidates_votes);
  free(accumulator);
}
