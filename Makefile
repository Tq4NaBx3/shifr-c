GCC = gcc
#GCC = gcc-8
SHIFR_OBJECTS = shifr.o main.o
SHIFR_ASM = shifr.s main.s
SHIFR_GCCRUN = $(GCC) $(SHDE) -Wall -Wextra -Winline -Wno-clobbered -std=c11 -Os
SHIFR_COMPILE = $(SHIFR_GCCRUN) -c 
DEPENDshifrh = shifr.h type.h
shifr: $(SHIFR_OBJECTS)
	@$(SHIFR_GCCRUN) $(SHIFR_OBJECTS) -o shifr
shifr.o: shifr.c $(DEPENDshifrh)
	@$(SHIFR_COMPILE) shifr.c
main.o: main.c $(DEPENDshifrh)
	@$(SHIFR_COMPILE) main.c
clean:
	@rm -f shifr
	@rm -f $(SHIFR_OBJECTS)
	@rm -f $(SHIFR_ASM)
debug asmdebug: SHDE = -DSHIFR_DEBUG
debug: shifr
asmdebug: asm
asm: $(SHIFR_ASM)
shifr.s: shifr.c $(DEPENDshifrh)
	@$(SHIFR_GCCRUN) shifr.c -S
main.s: main.c $(DEPENDshifrh)
	@$(SHIFR_GCCRUN) main.c -S
