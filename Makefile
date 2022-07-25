#
# Шифр ©2020-2 Глебов А.Н.
# Shifr ©2020-2 Glebe A.N.
#
GCC = gcc
#GCC = gcc-8
#GCC = gcc-9
CSTANDARD = -std=c11
#CSTANDARD = -std=c18
SHIFR_OBJECTS = shifr.o private.o
SHIFR_ASM = shifr.s main.s private.s
SHIFR_ASM_OPTIONS = -S -fverbose-asm
SHIFR_GCCRUN = $(GCC) -Wall -Wextra -Winline -Wshadow -Wconversion \
 -Wno-clobbered -Wpedantic \
 -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wfloat-equal \
 -Wcast-align -Wlogical-op -Wmissing-declarations -Wredundant-decls \
 -Werror=return-local-addr -Wbad-function-cast \
 -Wmissing-prototypes -Wnested-externs \
 -Wold-style-definition -Wstrict-prototypes \
 $(CSTANDARD) -Os
SHIFR_COMPILE = $(SHIFR_GCCRUN) -c 
DEPENDtypeh = type.h define.h
DEPENDtemplateh = template.h define.h
DEPENDprivateh = private.h $(DEPENDtypeh) $(DEPENDtemplateh)
DEPENDprivatec = private.c $(DEPENDprivateh) $(DEPENDstructh) define.h \
 $(DEPENDinlineprih)
DEPENDstructh = struct.h $(DEPENDtypeh) $(DEPENDtemplateh) template-pri.h
DEPENDpublich = public.h $(DEPENDtypeh) define.h
DEPENDinlineh = inline.h define.h $(DEPENDpublich) $(DEPENDstructh) \
 $(DEPENDinlineprih) $(DEPENDtemplateh) $(DEPENDprivateh) cast.h
DEPENDinlineprih = inline-pri.h template-pri.h cast.h
DEPENDmainc = main.c define.h $(DEPENDinlineh)
DEPENDshifrc = shifr.c define.h $(DEPENDinlineh) $(DEPENDtemplateh)
DEPENDexample = example.c define.h $(DEPENDinlineh)
EXAMPLE_OBJECTS = example.o
shifr: $(SHIFR_OBJECTS) main.o
	@$(SHIFR_GCCRUN) $(SHIFR_OBJECTS) main.o -o shifr
	@chmod 0555 shifr
shifr.o: $(DEPENDshifrc)
	@$(SHIFR_COMPILE) shifr.c
private.o: $(DEPENDprivatec)
	@$(SHIFR_COMPILE) private.c
main.o: $(DEPENDmainc)
	@$(SHIFR_COMPILE) main.c
clean:
	@rm -f shifr
	@rm -f $(SHIFR_OBJECTS)
	@rm -f main.o
	@rm -f $(SHIFR_ASM)
	@rm -f libshifr.so
	@rm -f example
	@rm -f example.s
asm: $(SHIFR_ASM)
shifr.s: $(DEPENDshifrc)
	@$(SHIFR_GCCRUN) shifr.c $(SHIFR_ASM_OPTIONS)
main.s: $(DEPENDmainc)
	@$(SHIFR_GCCRUN) main.c $(SHIFR_ASM_OPTIONS)
private.s: $(DEPENDprivatec)
	@$(SHIFR_GCCRUN) private.c $(SHIFR_ASM_OPTIONS)
lib: SHIFR_COMPILE += -mtune=native -fPIC
lib: $(SHIFR_OBJECTS)
	@$(GCC) -shared -fPIC $(SHIFR_OBJECTS) -o libshifr.so
	@chmod 0555 libshifr.so
	@sudo mkdir /usr/local/include/shifr || true
	@sudo cp *.h /usr/local/include/shifr
	@sudo cp libshifr.so /usr/local/lib
	@sudo ldconfig /usr/local/lib
example: $(EXAMPLE_OBJECTS) shifr.o private.o
	@$(SHIFR_GCCRUN) $(EXAMPLE_OBJECTS) shifr.o private.o -o example
example.o: $(DEPENDexample)
	@$(SHIFR_COMPILE) example.c
example.s: $(DEPENDexample)
	@$(SHIFR_GCCRUN) example.c $(SHIFR_ASM_OPTIONS)
