GCC = gcc
#GCC = gcc-8
shifr6: shifr6.c
	@$(GCC) -Wall -Wextra -Winline -Wno-clobbered -std=c11 -Os shifr6.c -o shifr6
clean:
	@rm -f shifr6
	@rm -f shifr6.s
asm: shifr6.s
shifr6.s: shifr6.c
	@$(GCC) -Wall -Wextra -Winline -Wno-clobbered -std=c11 -Os shifr6.c -S
