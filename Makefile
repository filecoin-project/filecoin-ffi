DEPS:=filecoin.h filecoin.pc libfilecoin.a

all: $(DEPS)
.PHONY: all

$(DEPS):
	./install-filecoin

clean:
	rm -rf $(DEPS)
.PHONY: clean
