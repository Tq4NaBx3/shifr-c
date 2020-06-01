GCC = gcc
#GCC = gcc-8
SHIFR_OBJECTS = shifr.o main.o
SHIFR_ASM = shifr.s main.s
SHIFR_GCCRUN = $(GCC) -Wall -Wextra -Winline -Wno-clobbered -std=c11 -Os
SHIFR_COMPILE = $(SHIFR_GCCRUN) -c 
DEPENDstructh = struct.h type.h
DEPENDpublich = public.h type.h define.h
DEPENDinlineh = inline.h $(DEPENDstructh) $(DEPENDpublich) define.h access.h
DEPENDmainc = main.c $(DEPENDinlineh) define.h
DEPENDshifrc = shifr.c $(DEPENDinlineh)
shifr: $(SHIFR_OBJECTS)
	@$(SHIFR_GCCRUN) $(SHIFR_OBJECTS) -o shifr
	@chmod 0555 shifr
shifr.o: $(DEPENDshifrc)
	@$(SHIFR_COMPILE) shifr.c
main.o: $(DEPENDmainc)
	@$(SHIFR_COMPILE) main.c
clean:
	@rm -f shifr
	@rm -f $(SHIFR_OBJECTS)
	@rm -f $(SHIFR_ASM)
	@rm -f libshifr.so
asm: $(SHIFR_ASM)
shifr.s: $(DEPENDshifrc)
	@$(SHIFR_GCCRUN) shifr.c -S
main.s: $(DEPENDmainc)
	@$(SHIFR_GCCRUN) main.c -S
lib: SHIFR_COMPILE += -mtune=native -fPIC
lib: $(SHIFR_OBJECTS)
	@$(GCC) -shared -fPIC $(SHIFR_OBJECTS) -o libshifr.so
	@chmod 0555 libshifr.so
	@sudo mkdir /usr/local/include/shifr || true
	@sudo cp *.h /usr/local/include/shifr
	@sudo cp libshifr.so /usr/local/lib
	@sudo ldconfig /usr/local/lib
