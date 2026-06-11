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
package io.contexa.contexaidentity.security.core.mfa.util;

/**
 * Centralized utility for MFA flow type detection and name generation.
 * All MFA flow detection logic should delegate to this class
 * instead of using scattered AuthType.MFA comparisons.
 */
public final class MfaFlowTypeUtils {

    private static final String MFA_BASE = "mfa";
    private static final String MFA_UNDERSCORE_PREFIX = MFA_BASE + "_";
    private static final String MFA_HYPHEN_PREFIX = MFA_BASE + "-";

    private MfaFlowTypeUtils() {
    }

    /**
     * Determines if a given flow typeName represents an MFA flow.
     * Matches: "mfa", "mfa_2", "mfa_admin", "mfa-stepup", etc.
     */
    public static boolean isMfaFlow(String typeName) {
        if (typeName == null) {
            return false;
        }
        String normalized = typeName.toLowerCase();
        return normalized.equals(MFA_BASE)
                || normalized.startsWith(MFA_UNDERSCORE_PREFIX)
                || normalized.startsWith(MFA_HYPHEN_PREFIX);
    }

    /**
     * Generates a unique MFA flow typeName with the given suffix.
     * Example: generateTypeName("admin") returns "mfa_admin"
     */
    public static String generateTypeName(String name) {
        if (name == null || name.isBlank()) {
            return MFA_BASE;
        }
        return MFA_UNDERSCORE_PREFIX + name.toLowerCase();
    }

    /**
     * Generates an auto-numbered MFA flow typeName.
     * count=1 returns "mfa", count=2 returns "mfa_2", count=3 returns "mfa_3"
     */
    public static String generateAutoNumberedTypeName(long existingMfaCount) {
        if (existingMfaCount <= 0) {
            return MFA_BASE;
        }
        return MFA_UNDERSCORE_PREFIX + (existingMfaCount + 1);
    }

    /**
     * Returns the base MFA type name constant.
     */
    public static String getBaseMfaTypeName() {
        return MFA_BASE;
    }
}
