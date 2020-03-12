DEPS:=filecoin.h filecoin.pc libfilecoin.a

all: $(DEPS)
.PHONY: all

$(DEPS):
	./install-filecoin

clean:
	rm ./generated/*.{go,h,c}
	rm -rf $(DEPS)
.PHONY: clean

lint: $(BUILD_DEPS)
	golangci-lint run -v --concurrency 2 --new-from-rev origin/master
.PHONY: lint

cgo-leakdetect: simulator
	./simulator
.PHONY: cgo-leakdetect

cgo-gen: $(BUILD_DEPS)
	c-for-go --ccincl --ccdefs --nostamp filecoin.yml
.PHONY: cgo-gen

simulator: $(BUILD_DEPS)
	rm -f ./simulator
	go build -o ./simulator ./cgoleakdetect/
.PHONY: simulator
