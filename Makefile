#
# Шифр ©2020-3 Глебов А.Н.
# Shifr ©2020-3 Glebe A.N.
#
GCC = gcc
#GCC = gcc-8
#GCC = gcc-9
CSTANDARD = -std=c11
#CSTANDARD = -std=c18
SHIFR_OBJECTS = o/shifr.o o/private.o o/number.o
SHIFR_ASM = s/shifr.s s/main.s s/private.s s/number.s
SHIFR_ASM_OPTIONS = -S -fverbose-asm
# for syscall
#USE_GNU_SOURCE = -D'_GNU_SOURCE'
USE_GNU_SOURCE =
SHIFR_INCLUDE = -I h $(USE_GNU_SOURCE)
# skip warning on static inline never defined
# COMPILEINLINE = -Wno-unused-function
# using inline warn's when code size grow
COMPILEINLINE =
SHIFR_GCCRUN = $(GCC) $(SHIFR_INCLUDE) -Wall -Wextra -Winline -Wshadow -Wconversion \
 -Wno-clobbered -Wpedantic -Werror=implicit-function-declaration \
 -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wfloat-equal \
 -Wcast-align -Wlogical-op -Wmissing-declarations -Wredundant-decls \
 -Werror=return-local-addr -Wbad-function-cast $(COMPILEINLINE) \
 -Werror=missing-prototypes -Wnested-externs -Werror=incompatible-pointer-types \
 -Wold-style-definition -Wstrict-prototypes -Werror=discarded-qualifiers \
 $(CSTANDARD) -Os
SHIFR_COMPILE = $(SHIFR_GCCRUN) -c 
EXAMPLE_OBJECTS = o/example.o $(SHIFR_OBJECTS)
EXAMPLE_ASM = s/example.s
OGCC = $(GCC) $(2) $(SHIFR_INCLUDE) -MM c/$(1).c -MT o/$(1).o > d/$(1).d && \
 $(SHIFR_COMPILE) $(2) -o o/$(1).o c/$(1).c
SGCC = $(GCC) $(2) $(SHIFR_INCLUDE) -MM c/$(1).c -MT s/$(1).s > s/$(1).d && \
 $(SHIFR_COMPILE) $(SHIFR_ASM_OPTIONS) $(2) -o s/$(1).s c/$(1).c
shifr: $(SHIFR_OBJECTS) o/main.o
	@$(SHIFR_GCCRUN) $(SHIFR_OBJECTS) o/main.o -o shifr
	@chmod 0555 shifr
o/shifr.o:
	@$(call OGCC,shifr)
o/number.o:
	@$(call OGCC,number)
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
s/number.s:
	@$(call SGCC,number)
s/private.s:
	@$(call SGCC,private)
s/main.s:
	@$(call SGCC,main)
lib: SHIFR_COMPILE += -mtune=native -fPIC
lib: $(SHIFR_OBJECTS)
	@$(GCC) -shared -fPIC $(SHIFR_OBJECTS) -o libshifr.so
	@chmod 0555 libshifr.so
	@sudo mkdir /usr/local/include/shifr || true
	@sudo cp h/*.h /usr/local/include/shifr
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
