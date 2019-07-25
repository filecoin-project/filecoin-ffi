DEPS:=sector_builder_ffi.h sector_builder_ffi.pc sector_builder_ffi.a

all: $(DEPS)
.PHONY: all


$(DEPS): .install-rust-fil-sector-builder  ;

.install-rust-fil-sector-builder: rust-fil-sector-builder
	./install-rust-fil-sector-builder
	@touch $@


clean:
	rm -rf $(DEPS) .install-rust-fil-sector-builder
.PHONY: clean
