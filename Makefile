GCC = gcc
#GCC = gcc-8
#GCC = gcc-9
CSTANDARD = -std=c11
#CSTANDARD = -std=c18
SHIFR_OBJECTS = shifr.o main.o
SHIFR_ASM = shifr.s main.s
SHIFR_ASM_OPTIONS = -S -fverbose-asm
SHIFR_GCCRUN = $(GCC) -Wall -Wextra -Winline -Wshadow -Wconversion -Wno-clobbered -Wpedantic \
 $(CSTANDARD) -Os
SHIFR_COMPILE = $(SHIFR_GCCRUN) -c 
DEPENDstructh = struct.h type.h
DEPENDpublich = public.h type.h define.h
DEPENDmainc = main.c define.h $(DEPENDpublich) $(DEPENDstructh) access.h
DEPENDshifrc = shifr.c $(DEPENDpublich) $(DEPENDstructh) access.h define.h
shifr: $(SHIFR_OBJECTS)
	@$(SHIFR_GCCRUN) $(SHIFR_OBJECTS) -o shifr
	@chmod 0555 shifr
shifr.o: $(DEPENDshifrc)
	@$(SHIFR_COMPILE) -D_GNU_SOURCE shifr.c
main.o: $(DEPENDmainc)
	@$(SHIFR_COMPILE) main.c
clean:
	@rm -f shifr
	@rm -f $(SHIFR_OBJECTS)
	@rm -f $(SHIFR_ASM)
	@rm -f libshifr.so
asm: $(SHIFR_ASM)
shifr.s: $(DEPENDshifrc)
	@$(SHIFR_GCCRUN) -D_GNU_SOURCE shifr.c $(SHIFR_ASM_OPTIONS)
main.s: $(DEPENDmainc)
	@$(SHIFR_GCCRUN) main.c $(SHIFR_ASM_OPTIONS)
lib: SHIFR_COMPILE += -mtune=native -fPIC
lib: $(SHIFR_OBJECTS)
	@$(GCC) -shared -fPIC $(SHIFR_OBJECTS) -o libshifr.so
	@chmod 0555 libshifr.so
	@sudo mkdir /usr/local/include/shifr || true
	@sudo cp *.h /usr/local/include/shifr
	@sudo cp libshifr.so /usr/local/lib
	@sudo ldconfig /usr/local/lib
