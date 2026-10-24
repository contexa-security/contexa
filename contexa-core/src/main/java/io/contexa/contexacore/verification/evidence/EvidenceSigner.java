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
package io.contexa.contexacore.verification.evidence;

import org.springframework.lang.Nullable;

/**
 * Signs the hashes of decision records and sealed evidence (docs/agent A5-6, AG-8): a keyed signature makes a changed
 * record whose hash was computed again detectable, which a plain hash cannot. Each signature names the key it was made
 * with, so records signed before a key change verify with their own key. The default signs with HMAC-SHA256
 * ({@link HmacEvidenceSigner}); declare a bean of this type to sign another way (a key service, an HSM).
 */
public interface EvidenceSigner {

    /** The key new signatures are made with. */
    String activeKeyId();

    /** The signature of the value under the active key. */
    String sign(String value);

    /**
     * Whether the signature is the value's under the named key; null when this signer does not hold that key (a record
     * signed before a restart with a key that was not kept), so the record cannot be verified rather than mismatched.
     */
    @Nullable
    Boolean verify(String keyId, String value, String signature);
}
