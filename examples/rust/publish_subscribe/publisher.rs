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

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use iceoryx2::prelude::*;
use iceoryx2_bb_container::semantic_string::*;
use iceoryx2_bb_posix::process::{Process, ProcessId};
use iceoryx2_cal::dynamic_storage::posix_shared_memory::*;
use iceoryx2_cal::named_concept::*;
use std::time::Duration;

enum ProcessType {
    Main,
    HotSwap,
    Obsolete,
}

#[derive(Debug, Copy, Clone)]
struct ProcessState {
    counter: u64,
}

impl ProcessState {
    fn new() -> Self {
        Self { counter: 0 }
    }
}

#[derive(Debug)]
struct SharedProcessState {
    pid_and_hotswap: AtomicU64,
    data: [UnsafeCell<ProcessState>; 2],
    cycle: AtomicUsize,
}

unsafe impl Send for SharedProcessState {}
unsafe impl Sync for SharedProcessState {}

impl SharedProcessState {
    fn new() -> Self {
        Self {
            pid_and_hotswap: AtomicU64::new(0),
            data: [
                UnsafeCell::new(ProcessState::new()),
                UnsafeCell::new(ProcessState::new()),
            ],
            cycle: AtomicUsize::new(0),
        }
    }

    fn next_cycle(&self) {
        let old_cycle = self.cycle.fetch_add(1, Ordering::AcqRel);
        unsafe { (*self.data[(old_cycle + 1) % 2].get()) = *self.data[(old_cycle) % 2].get() };
    }

    fn data(&self) -> &mut ProcessState {
        unsafe { &mut *self.data[self.cycle.load(Ordering::Relaxed) % 2].get() }
    }

    fn register(&self) -> ProcessType {
        let my_pid = Process::from_self().id().value();

        match self.pid_and_hotswap.compare_exchange(
            0,
            my_pid as u64,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => ProcessType::Main,
            Err(current_value) => {
                if (current_value >> 32) != 0 {
                    ProcessType::Obsolete
                } else {
                    let new_value = current_value | ((my_pid as u64) << 32);
                    match self.pid_and_hotswap.compare_exchange(
                        current_value,
                        new_value,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => ProcessType::HotSwap,
                        Err(_) => ProcessType::Obsolete,
                    }
                }
            }
        }
    }

    fn wait_for_main_death(&self) -> ProcessType {
        let current_value = self.pid_and_hotswap.load(Ordering::Relaxed);
        let parent_pid = (current_value & 0x00000000ffffffff) as i32;
        let monitor = Process::from_pid(ProcessId::new(parent_pid));

        while monitor.is_alive() {
            std::thread::yield_now();
        }

        match self.pid_and_hotswap.compare_exchange(
            current_value,
            current_value >> 32,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => ProcessType::Main,
            Err(_) => ProcessType::Obsolete,
        }
    }
}

fn start_hotswap() {
    let exe = std::env::current_exe().unwrap();
    std::process::Command::new(exe).spawn().unwrap();
}

fn main_process(shared_state: &SharedProcessState) -> Result<(), Box<dyn std::error::Error>> {
    let my_pid = Process::from_self().id().value();

    let node = NodeBuilder::new().create::<ipc::Service>()?;

    let service = node
        .service_builder(&"My/Funk/ServiceName".try_into()?)
        .publish_subscribe::<u64>()
        .open_or_create()?;

    let publisher = service.publisher_builder().create()?;

    loop {
        node.wait(Duration::from_millis(500));
        shared_state.next_cycle();

        shared_state.data().counter += 1;
        publisher.send_copy(shared_state.data().counter)?;

        println!(
            "pid: {}, counter {} - send data",
            my_pid,
            shared_state.data().counter
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Builder::new(&FileName::new(b"indestructible_process_state").unwrap())
        .open_or_create(SharedProcessState::new())
        .unwrap();

    let state = storage.get();
    match state.register() {
        ProcessType::Main => {
            println!("Start Main Process: {}", Process::from_self().id());
            start_hotswap();
            main_process(state)?;
        }
        ProcessType::HotSwap => {
            println!("Start HotSwap Process: {}", Process::from_self().id());
            state.wait_for_main_death();
            println!("Take over for dead Main Process");
            start_hotswap();
            main_process(&state)?;
        }
        ProcessType::Obsolete => {
            println!("Not needed, shutting down.");
        }
    };

    Ok(())
}
