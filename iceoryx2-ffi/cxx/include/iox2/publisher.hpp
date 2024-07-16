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

#ifndef IOX2_PUBLISHER_HPP
#define IOX2_PUBLISHER_HPP

#include "connection_failure.hpp"
#include "iox/assertions_addendum.hpp"
#include "iox/expected.hpp"
#include "sample_mut.hpp"
#include "service_type.hpp"
#include "unique_port_id.hpp"

#include <cstdint>

namespace iox2 {
enum class PublisherCreateError : uint8_t {
    /// The maximum amount of [`Publisher`]s that can connect to a
    /// [`Service`](crate::service::Service) is
    /// defined in [`crate::config::Config`]. When this is exceeded no more
    /// [`Publisher`]s
    /// can be created for a specific [`Service`](crate::service::Service).
    ExceedsMaxSupportedPublishers,
    /// The datasegment in which the payload of the [`Publisher`] is stored,
    /// could not be created.
    UnableToCreateDataSegment,
};

/// Defines a failure that can occur in [`Publisher::loan()`] and
/// [`Publisher::loan_uninit()`] or is part of [`PublisherSendError`] emitted in
/// [`Publisher::send_copy()`].
enum class PublisherLoanError : uint8_t {
    /// The [`Publisher`]s data segment does not have any more memory left
    OutOfMemory,
    /// The maximum amount of [`SampleMut`]s a user can borrow with
    /// [`Publisher::loan()`] or
    /// [`Publisher::loan_uninit()`] is
    /// defined in [`crate::config::Config`]. When this is exceeded those calls
    /// will fail.
    ExceedsMaxLoanedSamples,
    /// The provided slice size exceeds the configured max slice size of the
    /// [`Publisher`].
    /// To send a [`SampleMut`] with this size a new [`Publisher`] has to be
    /// created with
    /// a
    /// [`crate::service::port_factory::publisher::PortFactoryPublisher::max_slice_len()`]
    /// greater or equal to the required len.
    ExceedsMaxLoanSize,
    /// Errors that indicate either an implementation issue or a wrongly
    /// configured system.
    InternalFailure,
};

template <ServiceType S, typename Payload, typename UserHeader>
class Publisher {
  public:
    Publisher() = default;
    Publisher(Publisher&&) = default;
    auto operator=(Publisher&&) -> Publisher& = default;
    ~Publisher() = default;

    Publisher(const Publisher&) = delete;
    auto operator=(const Publisher&) -> Publisher& = delete;

    auto id() const -> UniquePublisherId {
        IOX_TODO();
    }
    auto send_copy(const Payload& payload) const -> iox::expected<uint64_t, PublisherSendError> {
        IOX_TODO();
    }

    auto loan_uninit() -> iox::expected<SampleMut<S, Payload, UserHeader>, PublisherLoanError> {
        IOX_TODO();
    }

    auto loan() -> iox::expected<SampleMut<S, Payload, UserHeader>, PublisherLoanError> {
        IOX_TODO();
    }

    auto loan_slice(const uint64_t number_of_elements)
        -> iox::expected<SampleMut<S, Payload, UserHeader>, PublisherLoanError> {
        IOX_TODO();
    }
    auto loan_slice_uninit(const uint64_t number_of_elements)
        -> iox::expected<SampleMut<S, Payload, UserHeader>, PublisherLoanError> {
        IOX_TODO();
    }

    auto update_connections() -> iox::expected<void, ConnectionFailure> {
        IOX_TODO();
    }
};
} // namespace iox2

#endif
