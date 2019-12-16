GCC = gcc
#GCC = gcc-8
shifr5	: shifr5.c
	@$(GCC) -Wall -std=c11 -Os shifr5.c -o shifr5
clean	:
	@rm shifr5
