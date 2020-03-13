DEPS:=filecoin.h filecoin.pc libfilecoin.a

all: $(DEPS)
.PHONY: all

$(DEPS):
	./install-filecoin

clean:
	rm -rf $(DEPS)
	rm -f ./runner
.PHONY: clean

lint: $(BUILD_DEPS)
	golangci-lint run -v --concurrency 2 --new-from-rev origin/master
.PHONY: lint

cgo-leakdetect: runner
	valgrind --leak-check=full --show-leak-kinds=definite ./runner
.PHONY: cgo-leakdetect

cgo-gen: $(BUILD_DEPS)
	c-for-go --ccincl --ccdefs --nostamp filecoin.yml
.PHONY: cgo-gen

runner: $(BUILD_DEPS)
	rm -f ./runner
	go build -o ./runner ./cgoleakdetect/
.PHONY: runner
