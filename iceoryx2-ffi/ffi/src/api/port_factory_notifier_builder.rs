// Copyright (c) 2024 Contributors to the Eclipse Foundation
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

#![allow(non_camel_case_types)]

use crate::api::{
    iox2_notifier_h, iox2_notifier_t, iox2_service_type_e, HandleToType, IntoCInt, NotifierUnion,
    IOX2_OK,
};

use iceoryx2::port::notifier::NotifierCreateError;
use iceoryx2::prelude::*;
use iceoryx2::service::port_factory::notifier::PortFactoryNotifier;
use iceoryx2_bb_elementary::static_assert::*;
use iceoryx2_ffi_macros::iceoryx2_ffi;

use core::ffi::c_int;
use core::mem::ManuallyDrop;

// BEGIN types definition

#[repr(C)]
#[derive(Copy, Clone)]
pub enum iox2_notifier_create_error_e {
    EXCEEDS_MAX_SUPPORTED_NOTIFIERS = IOX2_OK as isize + 1,
}

impl IntoCInt for NotifierCreateError {
    fn into_c_int(self) -> c_int {
        (match self {
            NotifierCreateError::ExceedsMaxSupportedNotifiers => {
                iox2_notifier_create_error_e::EXCEEDS_MAX_SUPPORTED_NOTIFIERS
            }
        }) as c_int
    }
}

pub(super) union PortFactoryNotifierBuilderUnion {
    ipc: ManuallyDrop<PortFactoryNotifier<'static, zero_copy::Service>>,
    local: ManuallyDrop<PortFactoryNotifier<'static, process_local::Service>>,
}

impl PortFactoryNotifierBuilderUnion {
    pub(super) fn new_ipc(port_factory: PortFactoryNotifier<'static, zero_copy::Service>) -> Self {
        Self {
            ipc: ManuallyDrop::new(port_factory),
        }
    }
    pub(super) fn new_local(
        port_factory: PortFactoryNotifier<'static, process_local::Service>,
    ) -> Self {
        Self {
            local: ManuallyDrop::new(port_factory),
        }
    }
}

#[repr(C)]
#[repr(align(8))] // alignment of Option<PortFactoryNotifierBuilderUnion>
pub struct iox2_port_factory_notifier_builder_storage_t {
    internal: [u8; 24], // magic number obtained with size_of::<Option<PortFactoryNotifierBuilderUnion>>()
}

#[repr(C)]
#[iceoryx2_ffi(PortFactoryNotifierBuilderUnion)]
pub struct iox2_port_factory_notifier_builder_t {
    service_type: iox2_service_type_e,
    value: iox2_port_factory_notifier_builder_storage_t,
    deleter: fn(*mut iox2_port_factory_notifier_builder_t),
}

impl iox2_port_factory_notifier_builder_t {
    pub(super) fn init(
        &mut self,
        service_type: iox2_service_type_e,
        value: PortFactoryNotifierBuilderUnion,
        deleter: fn(*mut iox2_port_factory_notifier_builder_t),
    ) {
        self.service_type = service_type;
        self.value.init(value);
        self.deleter = deleter;
    }
}

pub struct iox2_port_factory_notifier_builder_h_t;
/// The owning handle for `iox2_port_factory_notifier_builder_t`. Passing the handle to an function transfers the ownership.
pub type iox2_port_factory_notifier_builder_h = *mut iox2_port_factory_notifier_builder_h_t;

pub struct iox2_port_factory_notifier_builder_ref_h_t;
/// The non-owning handle for `iox2_port_factory_notifier_builder_t`. Passing the handle to an function does not transfers the ownership.
pub type iox2_port_factory_notifier_builder_ref_h = *mut iox2_port_factory_notifier_builder_ref_h_t;

impl HandleToType for iox2_port_factory_notifier_builder_h {
    type Target = *mut iox2_port_factory_notifier_builder_t;

    fn as_type(self) -> Self::Target {
        self as *mut _ as _
    }
}

impl HandleToType for iox2_port_factory_notifier_builder_ref_h {
    type Target = *mut iox2_port_factory_notifier_builder_t;

    fn as_type(self) -> Self::Target {
        self as *mut _ as _
    }
}

// END type definition

// BEGIN C API

// TODO [#210] add all the other setter methods

#[no_mangle]
pub unsafe extern "C" fn iox2_port_factory_notifier_builder_create(
    port_factory_handle: iox2_port_factory_notifier_builder_h,
    notifier_struct_ptr: *mut iox2_notifier_t,
    notifier_handle_ptr: *mut iox2_notifier_h,
) -> c_int {
    debug_assert!(!port_factory_handle.is_null());
    debug_assert!(!notifier_handle_ptr.is_null());

    let mut notifier_struct_ptr = notifier_struct_ptr;
    fn no_op(_: *mut iox2_notifier_t) {}
    let mut deleter: fn(*mut iox2_notifier_t) = no_op;
    if notifier_struct_ptr.is_null() {
        notifier_struct_ptr = iox2_notifier_t::alloc();
        deleter = iox2_notifier_t::dealloc;
    }
    debug_assert!(!notifier_struct_ptr.is_null());

    let notifier_builder_struct = unsafe { &mut *port_factory_handle.as_type() };

    let service_type = notifier_builder_struct.service_type;
    match service_type {
        iox2_service_type_e::IPC => {
            let notifier_builder =
                ManuallyDrop::take(&mut notifier_builder_struct.value.as_mut().ipc);

            match notifier_builder.create() {
                Ok(notifier) => {
                    (*notifier_struct_ptr).init(
                        service_type,
                        NotifierUnion::new_ipc(notifier),
                        deleter,
                    );
                }
                Err(error) => {
                    return error.into_c_int();
                }
            }
        }
        iox2_service_type_e::LOCAL => {
            let notifier_builder =
                ManuallyDrop::take(&mut notifier_builder_struct.value.as_mut().local);

            match notifier_builder.create() {
                Ok(notifier) => {
                    (*notifier_struct_ptr).init(
                        service_type,
                        NotifierUnion::new_local(notifier),
                        deleter,
                    );
                }
                Err(error) => {
                    return error.into_c_int();
                }
            }
        }
    }

    *notifier_handle_ptr = (*notifier_struct_ptr).as_handle();

    IOX2_OK
}

// END C API
