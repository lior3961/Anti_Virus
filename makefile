# Target to build the 'myshell' executable
all: AntiVirus

# Rule to link the 'myshell' executable
AntiVirus: AntiVirus.o
	gcc -m32 -g -Wall -o AntiVirus AntiVirus.o

# Rule to compile 'myshell.c' into 'myshell.o'
AntiVirus.o: AntiVirus.c
	gcc -m32 -g -Wall -c -o AntiVirus.o AntiVirus.c

# Phony target to clean up object files and the executable
.PHONY: clean
clean:
	rm -f *.o AntiVirus
