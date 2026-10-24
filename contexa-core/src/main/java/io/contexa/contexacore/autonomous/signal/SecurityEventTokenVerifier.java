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
package io.contexa.contexacore.autonomous.signal;

/**
 * Verifies a pushed Security Event Token (docs/agent A5-8): its signature by a configured transmitter, its issuer and
 * its audience. Contexa verifies the transmitters configured under {@code contexa.security.zerotrust.risk-signals};
 * a host declares its own bean to verify otherwise.
 */
@FunctionalInterface
public interface SecurityEventTokenVerifier {

    /** A token that does not verify, with the RFC 8935 error code it is answered with. */
    final class InvalidSecurityEventTokenException extends RuntimeException {

        private final String error;

        public InvalidSecurityEventTokenException(String error, String description) {
            super(description);
            this.error = error;
        }

        /** {@code invalid_request}, {@code invalid_key}, {@code invalid_issuer} or {@code invalid_audience}. */
        public String error() {
            return error;
        }
    }

    /**
     * @throws InvalidSecurityEventTokenException when the token does not verify
     */
    SecurityEventToken verify(String token);
}
