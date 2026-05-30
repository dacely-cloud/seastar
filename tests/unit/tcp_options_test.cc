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
 * Unit tests for the standards-compliance fixes added to net/tcp:
 *   - clamp_send_mss     (RFC 9293 / RFC 6691)
 *   - clamp_window_scale (RFC 7323 §2.3)
 *   - initial_cwnd_for_mss (RFC 6928 IW10)
 *   - tcp_option::fill() / get_size() emitting SACK_PERMITTED + SACK blocks
 *     (RFC 2018)
 *
 * The pieces under test are free functions / a plain struct that don't
 * require the full TCP template to be instantiated, so we test them
 * directly with Boost.Test.
 */

#define BOOST_TEST_MODULE tcp_options

#include <boost/test/unit_test.hpp>
#include <seastar/net/tcp.hh>
#include <array>
#include <cstring>

using namespace seastar;
using namespace seastar::net;

// ---------------------------------------------------------------------------
// clamp_send_mss
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(clamp_send_mss_caps_at_local) {
    // Peer announces a huge MSS (Windows w/ LSO can announce up to 16384+).
    // Our local MTU caps it at 1460.
    BOOST_CHECK_EQUAL(clamp_send_mss(16294, 1460), 1460);
    BOOST_CHECK_EQUAL(clamp_send_mss(65535, 1460), 1460);
    BOOST_CHECK_EQUAL(clamp_send_mss(9060, 1460), 1460);
}

BOOST_AUTO_TEST_CASE(clamp_send_mss_passes_smaller_peer) {
    // Peer is on a smaller MTU than us: use the peer's value.
    BOOST_CHECK_EQUAL(clamp_send_mss(536, 1460), 536);
    BOOST_CHECK_EQUAL(clamp_send_mss(1460, 9060), 1460);
    BOOST_CHECK_EQUAL(clamp_send_mss(1024, 1460), 1024);
}

BOOST_AUTO_TEST_CASE(clamp_send_mss_equal_values) {
    BOOST_CHECK_EQUAL(clamp_send_mss(1460, 1460), 1460);
    BOOST_CHECK_EQUAL(clamp_send_mss(9060, 9060), 9060);
}

// ---------------------------------------------------------------------------
// clamp_window_scale
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(clamp_window_scale_under_limit) {
    for (uint8_t s = 0; s <= 14; ++s) {
        BOOST_CHECK_EQUAL(clamp_window_scale(s), s);
    }
}

BOOST_AUTO_TEST_CASE(clamp_window_scale_over_limit) {
    BOOST_CHECK_EQUAL(clamp_window_scale(15), 14);
    BOOST_CHECK_EQUAL(clamp_window_scale(30), 14);
    BOOST_CHECK_EQUAL(clamp_window_scale(255), 14);
}

// ---------------------------------------------------------------------------
// initial_cwnd_for_mss (IW10, RFC 6928)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(iw10_at_mss_1460) {
    // Canonical case: standard Ethernet MSS gives the IW10 default of exactly
    // 10 segments (14600 bytes).
    BOOST_CHECK_EQUAL(initial_cwnd_for_mss(1460), 14600u);
}

BOOST_AUTO_TEST_CASE(iw10_at_jumbo_mss) {
    // Jumbo MSS: min(10*MSS, max(2*MSS, 14600)) collapses to 2*MSS because
    // 2*MSS already exceeds the 14600 floor and is below the 10*MSS ceiling.
    // For MSS=9060: max(18120, 14600)=18120, min(90600, 18120)=18120.
    BOOST_CHECK_EQUAL(initial_cwnd_for_mss(9060), 18120u);
    BOOST_CHECK_EQUAL(initial_cwnd_for_mss(8192), 16384u);
}

BOOST_AUTO_TEST_CASE(iw10_at_tiny_mss) {
    // Tiny MSS: 10*MSS is the smaller of the two arguments to min(), wins.
    // For MSS=536: max(1072, 14600)=14600, min(5360, 14600)=5360.
    BOOST_CHECK_EQUAL(initial_cwnd_for_mss(536),  5360u);
    BOOST_CHECK_EQUAL(initial_cwnd_for_mss(1000), 10000u);
}

BOOST_AUTO_TEST_CASE(iw10_at_boundary) {
    // Around MSS=1460 the formula transitions between regions.
    BOOST_CHECK_EQUAL(initial_cwnd_for_mss(1460), 14600u);  // exact 10*MSS == 14600
    BOOST_CHECK_EQUAL(initial_cwnd_for_mss(1461), 14600u);  // 10*MSS just above, capped at 14600
    BOOST_CHECK_EQUAL(initial_cwnd_for_mss(1459), 14590u);  // 10*MSS just below, wins via min
}

// ---------------------------------------------------------------------------
// tcp_option::get_size  -  must agree with fill() byte-for-byte
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(get_size_passive_syn_with_all_options) {
    // Server-side passive open: client's SYN had MSS, win_scale and
    // SACK_PERMITTED. We mirror all three in our SYN-ACK.
    // 4 (MSS) + 3 (win_scale) + 2 (SACK_permitted) + 1 (EOL) padded up = 12
    tcp_option opt;
    opt._mss_received = true;
    opt._win_scale_received = true;
    opt._sack_received = true;
    BOOST_CHECK_EQUAL(opt.get_size(/*syn_on=*/true, /*ack_on=*/true), 12);
}

BOOST_AUTO_TEST_CASE(get_size_passive_syn_without_sack) {
    // Peer didn't send SACK_PERMITTED: we don't either.
    // 4 + 3 + 1 EOL padded = 8
    tcp_option opt;
    opt._mss_received = true;
    opt._win_scale_received = true;
    opt._sack_received = false;
    BOOST_CHECK_EQUAL(opt.get_size(true, true), 8);
}

BOOST_AUTO_TEST_CASE(get_size_active_open_always_emits_all_three) {
    // Active open (no ack flag yet): we always advertise MSS + win_scale +
    // SACK_PERMITTED so the peer mirrors them back.
    tcp_option opt;
    BOOST_CHECK_EQUAL(opt.get_size(/*syn_on=*/true, /*ack_on=*/false), 12);
}

BOOST_AUTO_TEST_CASE(get_size_non_syn_no_sack_blocks) {
    // Plain ACK with nothing to advertise: no options.
    tcp_option opt;
    BOOST_CHECK_EQUAL(opt.get_size(/*syn_on=*/false, /*ack_on=*/true), 0);
}

BOOST_AUTO_TEST_CASE(get_size_non_syn_one_sack_block) {
    // ACK with one SACK block: 2 NOPs + 2 hdr + 8 = 12
    tcp_option opt;
    opt._sack_nblocks_out = 1;
    BOOST_CHECK_EQUAL(opt.get_size(false, true), 12);
}

BOOST_AUTO_TEST_CASE(get_size_non_syn_three_sack_blocks) {
    // ACK with three SACK blocks: 2 NOPs + 2 hdr + 24 = 28
    tcp_option opt;
    opt._sack_nblocks_out = 3;
    BOOST_CHECK_EQUAL(opt.get_size(false, true), 28);
}

BOOST_AUTO_TEST_CASE(get_size_non_syn_four_sack_blocks) {
    // Max blocks: 2 NOPs + 2 hdr + 32 = 36 (within the 40-byte option budget)
    tcp_option opt;
    opt._sack_nblocks_out = 4;
    BOOST_CHECK_EQUAL(opt.get_size(false, true), 36);
}

// ---------------------------------------------------------------------------
// tcp_option::fill  -  exact wire bytes
// ---------------------------------------------------------------------------

namespace {

// Build a minimal tcp_hdr just sufficient for fill() to read flag bits.
tcp_hdr make_hdr(bool syn, bool ack) {
    tcp_hdr h{};
    h.f_syn = syn;
    h.f_ack = ack;
    return h;
}

// Allocate a 60-byte zeroed buffer mimicking the bottom 20 bytes of a TCP
// header followed by up to 40 bytes of options.
std::array<uint8_t, 60> make_buf() {
    std::array<uint8_t, 60> b{};
    return b;
}

} // namespace

BOOST_AUTO_TEST_CASE(fill_passive_syn_all_three_options) {
    tcp_option opt;
    opt._mss_received = true;
    opt._win_scale_received = true;
    opt._sack_received = true;
    opt._local_mss = 1460;
    opt._local_win_scale = 7;

    auto hdr = make_hdr(/*syn=*/true, /*ack=*/true);
    auto buf = make_buf();
    auto wrote = opt.fill(buf.data(), &hdr, opt.get_size(true, true));
    BOOST_CHECK_EQUAL(wrote, 12u);

    // Bytes 0..19 are reserved for the TCP fixed header (untouched by fill).
    // Options start at offset 20.
    const uint8_t* o = buf.data() + tcp_hdr::len;
    // MSS option: kind=2, len=4, value=1460 big-endian = 0x05B4
    BOOST_CHECK_EQUAL(o[0], 0x02);
    BOOST_CHECK_EQUAL(o[1], 0x04);
    BOOST_CHECK_EQUAL(o[2], 0x05);
    BOOST_CHECK_EQUAL(o[3], 0xB4);
    // Window scale: kind=3, len=3, shift=7
    BOOST_CHECK_EQUAL(o[4], 0x03);
    BOOST_CHECK_EQUAL(o[5], 0x03);
    BOOST_CHECK_EQUAL(o[6], 0x07);
    // SACK_PERMITTED: kind=4, len=2
    BOOST_CHECK_EQUAL(o[7], 0x04);
    BOOST_CHECK_EQUAL(o[8], 0x02);
    // Padding NOPs + EOL to a multiple of 4. Total options = 12.
    // Three bytes of padding remain (offsets 9, 10, 11). At least one of
    // them must be an EOL (kind=0); preceding bytes are NOPs (kind=1).
    BOOST_CHECK(o[9] == 0x01 || o[9] == 0x00);
    BOOST_CHECK(o[10] == 0x01 || o[10] == 0x00);
    BOOST_CHECK_EQUAL(o[11], 0x00);
}

BOOST_AUTO_TEST_CASE(fill_non_syn_one_sack_block) {
    tcp_option opt;
    opt._sack_received = true;  // mostly informational on our side
    opt._sack_nblocks_out = 1;
    opt._sack_blocks_out[0] = {0x11111111u, 0x22222222u};

    auto hdr = make_hdr(/*syn=*/false, /*ack=*/true);
    auto buf = make_buf();
    auto sz = opt.get_size(false, true);
    BOOST_CHECK_EQUAL(sz, 12u);
    auto wrote = opt.fill(buf.data(), &hdr, sz);
    BOOST_CHECK_EQUAL(wrote, 12u);

    const uint8_t* o = buf.data() + tcp_hdr::len;
    // 2 NOPs for alignment
    BOOST_CHECK_EQUAL(o[0], 0x01);
    BOOST_CHECK_EQUAL(o[1], 0x01);
    // SACK option header: kind=5, len=10 (2 + 8*1)
    BOOST_CHECK_EQUAL(o[2], 0x05);
    BOOST_CHECK_EQUAL(o[3], 0x0A);
    // Block left edge (big endian)
    BOOST_CHECK_EQUAL(o[4], 0x11);
    BOOST_CHECK_EQUAL(o[5], 0x11);
    BOOST_CHECK_EQUAL(o[6], 0x11);
    BOOST_CHECK_EQUAL(o[7], 0x11);
    // Block right edge (big endian)
    BOOST_CHECK_EQUAL(o[8], 0x22);
    BOOST_CHECK_EQUAL(o[9], 0x22);
    BOOST_CHECK_EQUAL(o[10], 0x22);
    BOOST_CHECK_EQUAL(o[11], 0x22);
}

BOOST_AUTO_TEST_CASE(fill_non_syn_three_sack_blocks) {
    tcp_option opt;
    opt._sack_received = true;
    opt._sack_nblocks_out = 3;
    opt._sack_blocks_out[0] = {0xAAAAAAAAu, 0xBBBBBBBBu};
    opt._sack_blocks_out[1] = {0xCCCCCCCCu, 0xDDDDDDDDu};
    opt._sack_blocks_out[2] = {0xEEEEEEEEu, 0xFFFFFFFFu};

    auto hdr = make_hdr(false, true);
    auto buf = make_buf();
    auto sz = opt.get_size(false, true);
    BOOST_CHECK_EQUAL(sz, 28u);
    BOOST_CHECK_EQUAL(opt.fill(buf.data(), &hdr, sz), 28u);

    const uint8_t* o = buf.data() + tcp_hdr::len;
    BOOST_CHECK_EQUAL(o[0], 0x01);  // NOP
    BOOST_CHECK_EQUAL(o[1], 0x01);  // NOP
    BOOST_CHECK_EQUAL(o[2], 0x05);  // SACK kind
    BOOST_CHECK_EQUAL(o[3], 0x1A);  // len = 2 + 8*3 = 26
    // Three blocks, each 8 bytes
    for (int b = 0; b < 3; ++b) {
        uint8_t expect_l = uint8_t(0xAA + b * 0x22);
        uint8_t expect_r = uint8_t(0xBB + b * 0x22);
        for (int i = 0; i < 4; ++i) {
            BOOST_CHECK_EQUAL(o[4 + b * 8 + i], expect_l);
            BOOST_CHECK_EQUAL(o[8 + b * 8 + i], expect_r);
        }
    }
}

BOOST_AUTO_TEST_CASE(fill_non_syn_zero_blocks_zero_options) {
    // No SACK blocks pending and no SYN — fill() should emit nothing.
    tcp_option opt;
    auto hdr = make_hdr(false, true);
    auto buf = make_buf();
    BOOST_CHECK_EQUAL(opt.get_size(false, true), 0u);
    // fill() with options_size=0 should not touch the option region
    auto wrote = opt.fill(buf.data(), &hdr, 0);
    BOOST_CHECK_EQUAL(wrote, 0u);
    // Verify the option area is still all zeros
    for (size_t i = tcp_hdr::len; i < buf.size(); ++i) {
        BOOST_CHECK_EQUAL(buf[i], 0u);
    }
}

BOOST_AUTO_TEST_CASE(fill_active_syn_advertises_sack_permitted) {
    // Active open (we're the client). We unconditionally advertise SACK.
    tcp_option opt;
    opt._local_mss = 1460;
    opt._local_win_scale = 7;
    auto hdr = make_hdr(/*syn=*/true, /*ack=*/false);
    auto buf = make_buf();
    auto sz = opt.get_size(true, false);
    BOOST_CHECK_EQUAL(sz, 12u);
    opt.fill(buf.data(), &hdr, sz);

    const uint8_t* o = buf.data() + tcp_hdr::len;
    BOOST_CHECK_EQUAL(o[0], 0x02);  // MSS
    BOOST_CHECK_EQUAL(o[4], 0x03);  // win_scale
    BOOST_CHECK_EQUAL(o[7], 0x04);  // SACK_PERMITTED
    BOOST_CHECK_EQUAL(o[8], 0x02);  //   len
}
