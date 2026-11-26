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
package io.contexa.autoconfigure.ownership;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.springframework.lang.Nullable;

import java.util.List;

/**
 * The four ways of running Contexa the operating-mode plan asks for (docs/agent/운영모드-정상화-구현계획.md, R-1): the mode
 * as the application declares it on {@code @EnableAISecurity}, and the ownership of the sign-in as an operator sets it. The
 * two that follow the mode leave the ownership unset, as an application that never names it does; the two that cross the
 * mode name it.
 */
enum OperatingCombination {

    SANDBOX_HOST_OWNED(SecurityMode.SANDBOX, null),
    SANDBOX_CONTEXA_OWNED(SecurityMode.SANDBOX, SecurityOwnershipMode.CONTEXA_OWNED),
    FULL_HOST_OWNED(SecurityMode.FULL, SecurityOwnershipMode.HOST_OWNED),
    FULL_CONTEXA_OWNED(SecurityMode.FULL, null);

    private final SecurityMode mode;
    @Nullable
    private final SecurityOwnershipMode declaredOwnership;

    OperatingCombination(SecurityMode mode, @Nullable SecurityOwnershipMode declaredOwnership) {
        this.mode = mode;
        this.declaredOwnership = declaredOwnership;
    }

    /** The mode the application declares on its annotation. */
    SecurityMode mode() {
        return mode;
    }

    /** The settings that make this combination: the ownership where it crosses the mode, nothing otherwise. */
    List<String> properties() {
        return declaredOwnership == null ? List.of() : List.of(ContexaOperatingProfile.PROP_OWNERSHIP + "=" + declaredOwnership.name());
    }
}
