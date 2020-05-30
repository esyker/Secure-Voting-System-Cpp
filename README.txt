Para o funcionamento dos executáveis desenvolvidos são necessárias as seguintes bibliotecas:

https://github.com/Microsoft/SEAL

https://github.com/openssl/openssl
instalado localmente: ~/mylibs/ (ficheiro libseal-3.4.a em ~/mylibs/lib/ e ficheiros .h em ~/mylibs/include/SEAL-3.4)

https://github.com/dsprenkels/sss-cli
instalado em: ~/.cargo/bin/

Para compilar usa-se o makefile desenvolvido. São gerados os executáveis:
admin
voter
tally
counter

Deve executar-se em primeiro lugar o admin (./admin) onde se vai definir o número de candidatos, número de voters e número de trustees bem como o peso de cada voter.

Para cadaa voter executa-se o voter (./voter), onde é perguntado o número de votante e depois se procede à insersão dos candidatos a votar. A votação é escrita no ficheiro Urna.txt que se encontra no Ballot.

Para proceder à contagem dos votos executa-se o tally (./tally) que verifica qual o voto mais recentes válido de cada voter e procede à contagem.

O counter anuncia os resultados (./counter).




