GCC = gcc
#GCC = gcc-8
SHIFR_OBJECTS = shifr.o main.o
SHIFR_ASM = shifr.s main.s
SHIFR_GCCRUN = $(GCC) $(SHDE) -Wall -Wextra -Winline -Wno-clobbered -std=c11 -Os
SHIFR_COMPILE = $(SHIFR_GCCRUN) -c 
DEPENDstructh = struct.h type.h
DEPENDpublich = public.h type.h define.h
DEPENDinlineh = inline.h $(DEPENDstructh) $(DEPENDpublich) define.h access.h
DEPENDmainc = main.c $(DEPENDinlineh) define.h
DEPENDshifrc = shifr.c $(DEPENDinlineh)
shifr: $(SHIFR_OBJECTS)
	@$(SHIFR_GCCRUN) $(SHIFR_OBJECTS) -o shifr
shifr.o: $(DEPENDshifrc)
	@$(SHIFR_COMPILE) shifr.c
main.o: $(DEPENDmainc)
	@$(SHIFR_COMPILE) main.c
clean:
	@rm -f shifr
	@rm -f $(SHIFR_OBJECTS)
	@rm -f $(SHIFR_ASM)
debug asmdebug: SHDE = -DSHIFR_DEBUG
debug: shifr
asmdebug: asm
asm: $(SHIFR_ASM)
shifr.s: $(DEPENDshifrc)
	@$(SHIFR_GCCRUN) shifr.c -S
main.s: $(DEPENDmainc)
	@$(SHIFR_GCCRUN) main.c -S
