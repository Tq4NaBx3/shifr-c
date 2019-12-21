GCC = gcc
#GCC = gcc-8
shifr6	: shifr6.c
	@$(GCC) -Wall -std=c11 -Os shifr6.c -o shifr6
clean	:
	@rm shifr6
