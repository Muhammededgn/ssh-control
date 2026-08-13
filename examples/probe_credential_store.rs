//! Round-trips a throwaway entry through the OS credential store, then removes
//! it. Exists because the device-bound security modes are the one part of the
//! app that cannot be covered by unit tests — a real Secret Service has to be
//! running for them to work at all.
//!
//!     cargo run --example probe_credential_store
use ssh_control::config::device::{DeviceStore, credential_store_available};

fn main() {
    println!("credential store reachable: {}", credential_store_available());

    let store = DeviceStore::open("probe-throwaway").expect("open entry");
    println!("before write: {:?}", store.read().map(|s| s.is_some()));

    let state = ssh_control::config::device::DeviceState::new().expect("generate");
    store.write(&state).expect("write");

    let read_back = store.read().expect("read").expect("entry should exist");
    let matches = *read_back.device_key().unwrap() == *state.device_key().unwrap();
    println!("round-tripped device key matches: {matches}");

    store.delete();
    println!("after delete: {:?}", store.read().map(|s| s.is_some()));
}
