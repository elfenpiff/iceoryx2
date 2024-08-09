// Copyright (c) 2023 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache Software License 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0, or the MIT license
// which is available at https://opensource.org/licenses/MIT.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use iceoryx2_bb_container::semantic_string::*;
use iceoryx2_bb_posix::process::{Process, ProcessId};
use iceoryx2_cal::dynamic_storage::{posix_shared_memory::*, *};
use iceoryx2_cal::named_concept::*;
use std::time::Duration;

#[derive(Debug)]
struct SharedProcessState {
    pid: AtomicI32,
    hotswap_pid: AtomicI32,
    iteration: AtomicU64,
    fibonacci_1: AtomicU64,
    fibonacci_2: AtomicU64,
}

impl SharedProcessState {
    pub fn new() -> Self {
        Self {
            pid: AtomicI32::new(0),
            hotswap_pid: AtomicI32::new(0),
            iteration: AtomicU64::new(0),
            fibonacci_1: AtomicU64::new(0),
            fibonacci_2: AtomicU64::new(1),
        }
    }
}

fn main_process(state: &SharedProcessState) {
    let my_pid = Process::from_self().id().value();
    println!("Starting main process: {}", my_pid);

    if let Ok(exe) = std::env::current_exe() {
        std::process::Command::new(exe).spawn().unwrap();
    }

    loop {
        let n1 = state.fibonacci_1.load(Ordering::Relaxed);
        let n2 = state.fibonacci_2.load(Ordering::Relaxed);
        let n3 = n1.overflowing_add(n2).0;

        if state.iteration.fetch_add(1, Ordering::Relaxed) % 2 == 0 {
            state.fibonacci_1.store(n3, Ordering::Relaxed);
        } else {
            state.fibonacci_1.store(n2, Ordering::Relaxed);
            state.fibonacci_2.store(n3, Ordering::Relaxed);
        }

        println!("pid: {}, fibonacci {}", my_pid, n3);
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("start ...");
    let storage = Builder::new(&FileName::new(b"whatever").unwrap())
        .open_or_create(SharedProcessState::new())
        .unwrap();

    let state = storage.get();
    let my_pid = Process::from_self().id().value();

    match state
        .pid
        .compare_exchange(0, my_pid, Ordering::SeqCst, Ordering::SeqCst)
    {
        Ok(_) => main_process(state),
        Err(parent_pid) => {
            println!("Starting hotswap process: {}", my_pid);
            println!("observing pid: {}", parent_pid);
            state.hotswap_pid.store(my_pid, Ordering::SeqCst);

            let monitor = Process::from_pid(ProcessId::new(parent_pid));

            while monitor.is_alive() {
                std::thread::yield_now();
            }

            println!("taking over!");

            state.pid.store(my_pid, Ordering::SeqCst);
            state.hotswap_pid.store(0, Ordering::SeqCst);

            main_process(state);
        }
    };

    Ok(())
}
