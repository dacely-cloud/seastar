/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2014 Cloudius Systems, Ltd.
 */

#include <seastar/net/tcp.hh>
#include <seastar/net/tcp-stack.hh>
#include <seastar/net/ip.hh>
#include <seastar/core/align.hh>
#include <seastar/core/future.hh>
#include "net/native-stack-impl.hh"
#include <seastar/util/assert.hh>

namespace seastar {

namespace net {

// tcp_option::parse / fill / get_size are now defined inline in tcp.hh so
// they are usable from unit tests without linking the whole DPDK-laden
// libseastar.a. See include/seastar/net/tcp.hh.

ipv4_tcp::ipv4_tcp(ipv4& inet)
	: _inet_l4(inet), _tcp(std::make_unique<tcp<ipv4_traits>>(_inet_l4)) {
}

ipv4_tcp::~ipv4_tcp() {
}

void ipv4_tcp::received(packet p, ipv4_address from, ipv4_address to) {
    _tcp->received(std::move(p), from, to);
}

bool ipv4_tcp::forward(forward_hash& out_hash_data, packet& p, size_t off) {

    return _tcp->forward(out_hash_data, p, off);
}

server_socket
tcpv4_listen(tcp<ipv4_traits>& tcpv4, uint16_t port, listen_options opts) {
	return server_socket(std::make_unique<native_server_socket_impl<tcp<ipv4_traits>>>(
			tcpv4, port, opts));
}

::seastar::socket
tcpv4_socket(tcp<ipv4_traits>& tcpv4) {
    return ::seastar::socket(std::make_unique<native_socket_impl<tcp<ipv4_traits>>>(
            tcpv4));
}

}

}
