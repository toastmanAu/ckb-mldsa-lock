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

# ML-DSA parameter set (44 / 65 / 87). Default is 65 (NIST level 3).
# Override with: make MLDSA_PARAM=44   → produces build/mldsa44-lock
#                make MLDSA_PARAM=65   → produces build/mldsa-lock  (default)
#                make MLDSA_PARAM=87   → produces build/mldsa87-lock
MLDSA_PARAM ?= 65

# Validate value
ifneq ($(MLDSA_PARAM),44)
ifneq ($(MLDSA_PARAM),65)
ifneq ($(MLDSA_PARAM),87)
$(error MLDSA_PARAM must be 44, 65, or 87 (got: $(MLDSA_PARAM)))
endif
endif
endif

# Portable C, verify only
MLDSA_DEFS := \
    -DMLD_CONFIG_PARAMETER_SET=$(MLDSA_PARAM) \
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

BUILD   := build

# Default -65 build keeps the existing filename (backward compat with
# deployment scripts + test vectors). Non-default variants add the
# parameter as a suffix.
ifeq ($(MLDSA_PARAM),65)
TARGET  := $(BUILD)/mldsa-lock
else
TARGET  := $(BUILD)/mldsa$(MLDSA_PARAM)-lock
endif

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
