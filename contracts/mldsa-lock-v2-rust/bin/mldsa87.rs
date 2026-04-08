#![no_std]
#![no_main]

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

fn program_entry() -> i8 {
    mldsa_lock_v2_rust::entry::run(mldsa_lock_v2_rust::ParamId::Mldsa87)
}
