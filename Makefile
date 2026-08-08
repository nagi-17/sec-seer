all : src/main.c
	gcc src/main.c include/vector.c src/observer/observer.c -Iinclude -o main