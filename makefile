.PHONY: all clean

all: elflab

elflab: elflab.o
	gcc -o $@ $^

elflab.o: elflab.c
	gcc -c -o $@ $<

clean:
	rm -rf elflab elflab.o
