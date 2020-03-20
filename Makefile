DEPS:=filecoin.h filecoin.pc libfilecoin.a

all: $(DEPS)
.PHONY: all

# Create a file so that parallel make doesn't call `./install-filecoin` for
# each of the deps
$(DEPS): .install-filecoin  ;

.install-filecoin: rust
	./install-filecoin
	@touch $@

clean:
	rm -rf $(DEPS) .install-filecoin
	rm -f ./runner
.PHONY: clean

lint: $(DEPS)
	golangci-lint run -v --concurrency 2 --new-from-rev origin/master
.PHONY: lint

cgo-leakdetect: runner
	valgrind --leak-check=full --show-leak-kinds=definite ./runner
.PHONY: cgo-leakdetect

cgo-gen: $(DEPS)
	c-for-go --ccincl --ccdefs --nostamp filecoin.yml
.PHONY: cgo-gen

runner: $(DEPS)
	rm -f ./runner
	go build -o ./runner ./cgoleakdetect/
.PHONY: runner
