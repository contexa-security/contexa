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
package io.contexa.contexacore.autonomous.context.support;

import org.springframework.lang.Nullable;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Network blocks (CIDR, IPv4 or IPv6) and the addresses they hold. A block without a prefix length is one address.
 * Only address literals are read: no name is ever resolved.
 */
public final class NetworkBlocks {

    private NetworkBlocks() {
    }

    /**
     * Whether the block holds the address; null when either is missing or they are not comparable (not literals, or
     * one IPv4 and the other IPv6): then it is not known, not held.
     */
    @Nullable
    public static Boolean contains(@Nullable String block, @Nullable String address) {
        if (block == null || block.isBlank() || address == null || address.isBlank()) {
            return null;
        }
        String[] parts = block.trim().split("/");
        if (parts.length > 2) {
            return null;
        }
        byte[] ip = literal(address.trim());
        byte[] base = literal(parts[0].trim());
        if (ip == null || base == null || ip.length != base.length) {
            return null;
        }
        Integer length = prefix(parts, ip.length * 8);
        if (length == null) {
            return null;
        }
        for (int bit = 0; bit < length; bit++) {
            int mask = 0x80 >> (bit % 8);
            if ((ip[bit / 8] & mask) != (base[bit / 8] & mask)) {
                return false;
            }
        }
        return true;
    }

    /** Whether the text is a network block: an address literal with an optional prefix length that fits it. */
    public static boolean valid(@Nullable String block) {
        if (block == null || block.isBlank()) {
            return false;
        }
        String[] parts = block.trim().split("/");
        if (parts.length > 2) {
            return false;
        }
        byte[] base = literal(parts[0].trim());
        return base != null && prefix(parts, base.length * 8) != null;
    }

    @Nullable
    private static Integer prefix(String[] parts, int bits) {
        if (parts.length < 2) {
            return bits;
        }
        try {
            int length = Integer.parseInt(parts[1].trim());
            return length < 0 || length > bits ? null : length;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** The bytes of an IPv4 or IPv6 address literal, null for anything else; no name is resolved. */
    @Nullable
    private static byte[] literal(String address) {
        if (address.contains(":")) {
            if (!address.matches("[0-9A-Fa-f:.]+")) {
                return null;
            }
            try {
                return InetAddress.getByName(address).getAddress();
            } catch (UnknownHostException e) {
                return null;
            }
        }
        Long value = ipv4(address);
        if (value == null) {
            return null;
        }
        return new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) (value & 0xFF)};
    }

    @Nullable
    private static Long ipv4(String address) {
        String[] octets = address.trim().split("\\.");
        if (octets.length != 4) {
            return null;
        }
        long value = 0;
        for (String octet : octets) {
            try {
                int part = Integer.parseInt(octet);
                if (part < 0 || part > 255) {
                    return null;
                }
                value = (value << 8) | part;
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return value;
    }
}
