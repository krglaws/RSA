
CC := gcc
CFLAGS := -fPIC -Iinclude -std=c99

SRC := ./src
INC := ./include
BIN := ./bin

INCLOC := /usr/include
LIBLOC := /usr/lib

default: all


RSADEPS := $(SRC)/rsa.c
RSATARG := $(BIN)/rsa.o

$(RSATARG): $(RSADEPS)
	$(CC) -c $< -o $@ $(CFLAGS)


STATICLIB := librsa.a

$(STATICLIB): $(RSATARG)
	ar rcs $@ $<


DYNAMICLIB := librsa.so

$(DYNAMICLIB): $(RSATARG)
	gcc -shared -o $@ $<


.PHONY: install
install:
	@cp $(STATICLIB) $(LIBLOC)
	@cp $(DYNAMICLIB) $(LIBLOC)
	@cp $(INC)/* $(INCLOC)
	@echo "Installed successfully."


.PHONY: uninstall
uninstall:
	@if [ -f $(INCLOC)/rsa.h ]; then rm -rf $(INCLOC)/rsa.h; fi;
	@if [ -f $(LIBLOC)/$(STATICLIB) ]; then rm $(LIBLOC)/$(STATICLIB); fi;
	@if [ -f $(LIBLOC)/$(DYNAMICLIB) ]; then rm $(LIBLOC)/$(DYNAMICLIB); fi;


.PHONY: clean
clean:
	@if [ -f $(RSATARG) ]; then rm $(RSATARG); fi;
	@if [ -f $(STATICLIB) ]; then rm $(STATICLIB); fi;
	@if [ -f $(DYNAMICLIB) ]; then rm $(DYNAMICLIB); fi;


.PHONY: all 
all:
	@echo "building static library..."
	$(MAKE) $(STATICLIB)
	@echo "done."
	@echo "building dynamic library..."
	$(MAKE) $(DYNAMICLIB)
	@echo "done."

