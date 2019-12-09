DEPS:=filecoin.h filecoin.pc libfilecoin.a

all: $(DEPS)
	./install-filecoin
.PHONY: all

clean:
	rm -rf $(DEPS)
.PHONY: clean
