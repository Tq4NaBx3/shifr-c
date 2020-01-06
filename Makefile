GCC = gcc
#GCC = gcc-8
shifr: shifr.c
	@$(GCC) $(SHDE) -Wall -Wextra -Winline -Wno-clobbered -std=c11 -Os shifr.c -o shifr
clean:
	@rm -f shifr
	@rm -f shifr.s
debug asmdebug: SHDE = -DSHIFR_DEBUG
debug: shifr
asmdebug: asm
asm: shifr.s
shifr.s: shifr.c
	@$(GCC) $(SHDE) -Wall -Wextra -Winline -Wno-clobbered -std=c11 -Os shifr.c -S
