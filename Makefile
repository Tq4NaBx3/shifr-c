#
# Шифр ©2020-3 Глебов А.Н.
# Shifr ©2020-3 Glebe A.N.
#
GCC = gcc
#GCC = gcc-8
#GCC = gcc-9
CSTANDARD = -std=c11
#CSTANDARD = -std=c18
SHIFR_OBJECTS = o/shifr.o o/private.o
SHIFR_ASM = s/shifr.s s/main.s s/private.s
SHIFR_ASM_OPTIONS = -S -fverbose-asm
SHIFR_GCCRUN = $(GCC) -Wall -Wextra -Winline -Wshadow -Wconversion \
 -Wno-clobbered -Wpedantic -Werror=implicit-function-declaration \
 -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wfloat-equal \
 -Wcast-align -Wlogical-op -Wmissing-declarations -Wredundant-decls \
 -Werror=return-local-addr -Wbad-function-cast \
 -Werror=missing-prototypes -Wnested-externs -Werror=incompatible-pointer-types \
 -Wold-style-definition -Wstrict-prototypes -Werror=discarded-qualifiers \
 $(CSTANDARD) -Os
SHIFR_COMPILE = $(SHIFR_GCCRUN) -c 
EXAMPLE_OBJECTS = o/example.o $(SHIFR_OBJECTS)
EXAMPLE_ASM = s/example.s
OGCC = $(GCC) $(2) -I . -MM $(1).c -MT o/$(1).o > d/$(1).d && \
 $(SHIFR_COMPILE) $(2) -o o/$(1).o $(1).c
SGCC = $(GCC) $(2) -I . -MM $(1).c -MT s/$(1).s > s/$(1).d && \
 $(SHIFR_COMPILE) $(SHIFR_ASM_OPTIONS) $(2) -o s/$(1).s $(1).c
shifr: $(SHIFR_OBJECTS) o/main.o
	@$(SHIFR_GCCRUN) $(SHIFR_OBJECTS) o/main.o -o shifr
	@chmod 0555 shifr
o/shifr.o:
	@$(call OGCC,shifr)
o/private.o:
	@$(call OGCC,private)
o/main.o:
	@$(call OGCC,main)
clean:
	@rm -f shifr
	@rm -f libshifr.so
	@rm -f example
	@rm -f d/*.d s/*.d s/*.s o/*.o
asm: $(SHIFR_ASM)
s/shifr.s:
	@$(call SGCC,shifr)
s/private.s:
	@$(call SGCC,private)
s/main.s:
	@$(call SGCC,main)
lib: SHIFR_COMPILE += -mtune=native -fPIC
lib: $(SHIFR_OBJECTS)
	@$(GCC) -shared -fPIC $(SHIFR_OBJECTS) -o libshifr.so
	@chmod 0555 libshifr.so
	@sudo mkdir /usr/local/include/shifr || true
	@sudo cp *.h /usr/local/include/shifr
	@sudo cp libshifr.so /usr/local/lib
	@sudo ldconfig /usr/local/lib
example_asm: $(EXAMPLE_ASM)
example: $(EXAMPLE_OBJECTS)
	@$(SHIFR_GCCRUN) $(EXAMPLE_OBJECTS) -o example
o/example.o:
	@$(call OGCC,example)
s/example.s:
	@$(call SGCC,example)

-include d/*.d
-include s/*.d
