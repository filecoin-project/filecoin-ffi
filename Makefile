DEPS:=ffi-common.h filcrypto-v1.h filcrypto-v2.h filcrypto-v1.pc filcrypto-v2.pc libfilcrypto_v1.a libfilcrypto_v2.a

all: $(DEPS)
.PHONY: all

# Create a file so that parallel make doesn't call `./install-filcrypto` for
# each of the deps
$(DEPS): .install-filcrypto  ;

.install-filcrypto: rust
	./install-filcrypto
	@touch $@

clean:
	rm -rf $(DEPS) .install-filcrypto
	rm -f ./runner
	cd rust && cargo clean && cd ..
.PHONY: clean

go-lint: $(DEPS)
	golangci-lint run -v --concurrency 2 --new-from-rev origin/master
.PHONY: go-lint

shellcheck:
	shellcheck install-filcrypto

lint: shellcheck go-lint

cgo-leakdetect: runner
	valgrind --leak-check=full --show-leak-kinds=definite ./runner
.PHONY: cgo-leakdetect

cgo-gen: $(DEPS)
	go run github.com/xlab/c-for-go --nostamp filcrypto-v1.yml
	go run github.com/xlab/c-for-go --nostamp filcrypto-v2.yml
        # Replace duplicate generated (shared/common) symbols
        #
        # FIXME: Ideally this shouldn't be needed -- the symbols are already in ffi-common.h, but since they are
        # used in rust api-v1 and api-v2, it's generated again in each header and must be removed.
        # The nasty sed lines are really just deleting a range of lines that could look like this:
        # sed -i "${LINE_START},${LINE_END}d" filcrypto-v1.h
	sed -i "$(shell grep -n 'typedef enum {' filcrypto-v1.h  | head -n 1 | cut -d':' -f 1),$(shell grep -n 'FCPResponseStatus;' filcrypto-v1.h  | head -n 1 | cut -d':' -f 1)d" filcrypto-v1.h
	sed -i "$(shell grep -n 'typedef enum {' filcrypto-v2.h  | head -n 1 | cut -d':' -f 1),$(shell grep -n 'FCPResponseStatus;' filcrypto-v2.h  | head -n 1 | cut -d':' -f 1)d" filcrypto-v2.h
.PHONY: cgo-gen

runner: $(DEPS)
	rm -f ./runner
	go build -o ./runner ./cgoleakdetect/
.PHONY: runner
