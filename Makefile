GCC = gcc
#GCC = gcc-8
shifr4	: shifr4.c
	@$(GCC) -Wall -std=c11 -Os shifr4.c -o shifr4
clean	:
	@rm shifr4
