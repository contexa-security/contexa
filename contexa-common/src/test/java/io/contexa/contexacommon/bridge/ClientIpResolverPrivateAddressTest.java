/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.network.ClientIpResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** Only the socket's address decides, and whatever is no plain address counts as a public one. */
class ClientIpResolverPrivateAddressTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "not-an-address", "localhost", "127.0.0.1.nip.io", "10.0.0.1.evil.example", "evil.example", "unknown",
            "999.1.1.1", "10.0.0.256", "10.0.0", "10.0.0.1.1", "127.1", "0x7f.0.0.1", "2130706433", "017700000001",
            "010.0.0.1", "127.000.000.001", "10.0.0.1:8080", "10.0.0.1/8", "10.0.0.1%eth0", "10.0.0.1,203.0.113.7",
            "::ffff:999.1.1.1", ":::1", "fe80::1::2", "fc00::g", ".:", "[10.0.0.1]", "[::1", "::1]", "[]", "%eth0"})
    @DisplayName("what is no plain address is never private, and no name is looked up to find out")
    void whatIsNoAddressIsNotPrivate(String value) {
        assertThat(ClientIpResolver.isPrivateOrLoopback(value)).isFalse();
    }

    @Test
    @DisplayName("no address at all is not private either")
    void noAddress() {
        assertThat(ClientIpResolver.isPrivateOrLoopback(null)).isFalse();
        assertThat(ClientIpResolver.isPrivateOrLoopback("")).isFalse();
        assertThat(ClientIpResolver.isPrivateOrLoopback("   ")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "203.0.113.7", "8.8.8.8", "9.255.255.255", "11.0.0.0", "126.255.255.255", "128.0.0.0", "172.15.255.255",
            "172.32.0.0", "192.167.255.255", "192.169.0.0", "169.253.255.255", "169.255.0.0", "100.64.0.1", "0.0.0.0",
            "255.255.255.255", "224.0.0.1"})
    @DisplayName("an IPv4 address outside the ranges is public, right up to their edges")
    void publicIpv4(String address) {
        assertThat(ClientIpResolver.isPrivateOrLoopback(address)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "::", "::2", "2001:db8::1", "2606:4700:4700::1111", "fbff:ffff::1", "fe00::1", "fe7f::1", "fec0::1", "ff02::1",
            "::ffff:203.0.113.7", "::ffff:cb00:7107", "::ffff:8.8.8.8", "::127.0.0.1", "::10.0.0.1", "64:ff9b::a00:1",
            "2002:a00:1::", "[2001:db8::1]"})
    @DisplayName("an IPv6 address outside the ranges is public, and what only carries a private one inside it too")
    void publicIpv6(String address) {
        assertThat(ClientIpResolver.isPrivateOrLoopback(address)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "127.0.0.1", "127.255.255.254", "10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0",
            "192.168.255.255", "169.254.0.1", "169.254.255.254", " 10.0.0.1 "})
    @DisplayName("loopback, the private ranges and link-local are private, up to their last address")
    void privateIpv4(String address) {
        assertThat(ClientIpResolver.isPrivateOrLoopback(address)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001", "[::1]", "fc00::", "fc00::1",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "FD12:3456::1", "fe80::", "fe80::1", "febf:ffff::1", "fe80::1%eth0",
            "fe80:0:0:0:1:2:3:4%4", "[fe80::1%eth0]"})
    @DisplayName("IPv6 loopback, unique local (fc00::/7) and link-local (fe80::/10) are private, in every spelling")
    void privateIpv6(String address) {
        assertThat(ClientIpResolver.isPrivateOrLoopback(address)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"::ffff:10.0.0.5", "::ffff:127.0.0.1", "::ffff:192.168.1.1", "::ffff:a00:5", "::FFFF:7f00:1",
            "0:0:0:0:0:ffff:a00:5"})
    @DisplayName("an IPv4 address mapped into IPv6 counts as the address it is")
    void mappedAddresses(String address) {
        assertThat(ClientIpResolver.isPrivateOrLoopback(address)).isTrue();
    }
}
