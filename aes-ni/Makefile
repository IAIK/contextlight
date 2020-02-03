all: context-light aes
	gcc main.o context-light-nop.o -o aes
	gcc main-context.o context-light.o -o aes-context
	
context-light: ../context-light.c ../context-light.h
	gcc -c ../context-light.c -o context-light.o -I../module
	gcc -c ../context-light.c -o context-light-nop.o -DNOSPEC_DISABLE -I../module
	
aes: main.c aes-ni.h
	gcc -c main.c -march=native -O3 -o main-context.o
	gcc -c main.c -march=native -O3 -DNOSPEC_DISABLE -o main.o

clean:
	rm -f *.o aes aes-context
	
