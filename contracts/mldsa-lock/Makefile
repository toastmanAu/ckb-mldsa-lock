CC      := riscv64-unknown-elf-gcc
AR      := riscv64-unknown-elf-ar
OBJCOPY := riscv64-unknown-elf-objcopy

# CKB-VM RISC-V target: RV64IMC, no OS, no stdlib
CFLAGS := \
    -Os \
    -g0 \
    -ffunction-sections \
    -fdata-sections \
    -fvisibility=hidden \
    -fno-builtin \
    -nostdinc \
    -nostdlib \
    -march=rv64imc \
    -mabi=lp64 \
    -Wall \
    -Wno-unused-function

LDFLAGS := \
    -Wl,--gc-sections \
    -Wl,-static \
    -nostdlib \
    -T ckb_link.ld

VENDOR  := vendor/mldsa-native
MLDSA   := $(VENDOR)/mldsa
FIPS    := $(MLDSA)/src/fips202

GCC_RISCV_INCLUDE := $(shell riscv64-unknown-elf-gcc -print-file-name=include)

INCLUDES := \
    -I src \
    -I $(VENDOR)/mldsa \
    -I $(MLDSA)/src \
    -I deps/ckb-c-stdlib \
    -I deps/molecule \
    -I $(GCC_RISCV_INCLUDE) \
    -I /usr/include/newlib

# ML-DSA-65 only, portable C, verify only
MLDSA_DEFS := \
    -DMLD_CONFIG_PARAMETER_SET=65 \
    -DMLDSA_NATIVE_PORTABLE=1 \
    -DMLDSA_NO_SIGN=1 \
    -DMLDSA_NO_KEYGEN=1 \
    -DMLDSA_RANDOMIZED_SIGNING=0

# Source files — mldsa_native.c is an SCU (single compilation unit)
# that already #includes packing.c, poly.c, polyvec.c, ct.c, fips202.c, keccakf1600.c.
# Compile only the SCU; do NOT list the constituent files separately.
MLDSA_SRCS := \
    $(MLDSA)/mldsa_native.c

CONTRACT_SRCS := \
    src/startup.S \
    src/sys.c \
    src/entry.c \
    src/mldsa_adapter.c

ALL_SRCS := $(CONTRACT_SRCS) $(MLDSA_SRCS)

TARGET  := build/mldsa-lock
BUILD   := build

.PHONY: all clean size

all: $(TARGET)

$(BUILD):
	mkdir -p $(BUILD)

$(TARGET): $(BUILD) $(ALL_SRCS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) $(INCLUDES) $(MLDSA_DEFS) \
	    -o $@ $(ALL_SRCS)
	$(OBJCOPY) --strip-all $@
	@echo ""
	@echo "Build complete: $@"
	@$(MAKE) size

size: $(TARGET)
	@echo "Binary size:"
	@ls -lh $(TARGET) | awk '{print "  " $$5 "  " $$9}'
	@riscv64-unknown-elf-size $(TARGET)

clean:
	rm -rf $(BUILD)

# Fetch CKB C stdlib and molecule headers if not present
deps/ckb-c-stdlib:
	git clone --depth=1 https://github.com/nervosnetwork/ckb-c-stdlib deps/ckb-c-stdlib

deps/molecule:
	git clone --depth=1 https://github.com/nervosnetwork/molecule deps/molecule-repo
	mkdir -p deps/molecule
	cp deps/molecule-repo/bindings/c/include/*.h deps/molecule/

deps: deps/ckb-c-stdlib deps/molecule
