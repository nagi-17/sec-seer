all : src/main.c
	gcc src/main.c include/vector.c src/observer/observer.c src/policy-translator/json-deserializer/json-parser.c src/policy-translator/json-deserializer/parson.c -Iinclude -o main