all: example example_secured

example: main.c cacheutils.h ../context-light.h ../context-light.c
	clang main.c ../context-light.c -o example -Os -I../module

example_secured: main.c cacheutils.h ../context-light.h ../context-light.c
	clang main.c ../context-light.c -o example_secured -Os -DSECURE -I../module

clean:
	rm -f example example_secured
