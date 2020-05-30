all: admin voter tally counter clean

admin: admin.o
	g++ -o admin admin.o ~/mylibs/lib/libseal-3.4.a -lpthread -Wall

voter: voter.o
	g++ -o voter voter.o ~/mylibs/lib/libseal-3.4.a -lpthread -Wall

tally: tally.o
	g++ -o tally tally.o ~/mylibs/lib/libseal-3.4.a -lpthread -Wall

counter: counter.o
	g++ -o counter counter.o ~/mylibs/lib/libseal-3.4.a -lpthread -Wall


admin.o: admin.cpp defs.h
	 g++ -std=c++1z -o admin.o -c admin.cpp -I ~/mylibs/include/SEAL-3.4 -Wall

voter.o: voter.cpp defs.h
	 g++ -std=c++1z -o voter.o -c voter.cpp -I ~/mylibs/include/SEAL-3.4 -Wall

tally.o: tally.cpp defs.h
	 g++ -std=c++1z -o tally.o -c tally.cpp -I ~/mylibs/include/SEAL-3.4 -Wall

counter.o: counter.cpp defs.h
	 g++ -std=c++1z -o counter.o -c counter.cpp -I ~/mylibs/include/SEAL-3.4 -Wall
clean:
	rm -rf *.o
