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
package io.contexa.contexacommon.operating;

import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.springframework.core.env.Environment;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * How an application runs Contexa, read once and in one place. There are two ways: SANDBOX, where an existing application
 * keeps its sign-in (HOST_OWNED), and FULL, where Contexa owns the sign-in of a new one (CONTEXA_OWNED). The two settings
 * name the same choice, so settings that disagree describe no way of running Contexa and are refused.
 *
 * @param mode                       the way of running Contexa
 * @param ownership                  who owns the sign-in
 * @param contexaOwnsApplicationData whether Contexa's database is the application's database as well
 * @param declaredDatabaseUnused     whether the application names a database of its own and Contexa's serves instead
 */
public record ContexaOperatingProfile(SecurityMode mode, SecurityOwnershipMode ownership, boolean contexaOwnsApplicationData,
                                      boolean declaredDatabaseUnused) {

    public static final String PROP_MODE = "contexa.ai.security.mode";
    public static final String PROP_OWNERSHIP = "contexa.bridge.ownership";
    public static final String PROP_APPLICATION_DATA = "contexa.datasource.isolation.contexa-owned-application";

    /** The profile of a running application: the mode as the annotation published it. */
    public static ContexaOperatingProfile resolve(Environment environment) {
        return of(read(environment, PROP_MODE, SecurityMode.class), environment);
    }

    /** The profile of an application that declares this mode; without a mode, its ownership stands alone. */
    public static ContexaOperatingProfile of(@Nullable SecurityMode declaredMode, Environment environment) {
        SecurityOwnershipMode declaredOwnership = read(environment, PROP_OWNERSHIP, SecurityOwnershipMode.class);
        if (declaredMode != null && declaredOwnership != null && ownershipOf(declaredMode) != declaredOwnership) {
            throw disagreement(declaredMode, declaredOwnership);
        }
        SecurityOwnershipMode ownership = declaredOwnership != null ? declaredOwnership : ownershipOf(declaredMode);
        SecurityMode mode = declaredMode != null ? declaredMode : modeOf(ownership);
        boolean applicationData = applicationData(ownership, environment);
        return new ContexaOperatingProfile(mode, ownership, applicationData, applicationData && !sameDatabaseOrNone(environment));
    }

    /** Whether this application declares the ownership at all; an application with Contexa dormant does not. */
    public static boolean ownershipUndeclared(Environment environment) {
        return !StringUtils.hasText(environment.getProperty(PROP_OWNERSHIP));
    }

    private static SecurityOwnershipMode ownershipOf(@Nullable SecurityMode mode) {
        return mode == SecurityMode.FULL ? SecurityOwnershipMode.CONTEXA_OWNED : SecurityOwnershipMode.HOST_OWNED;
    }

    private static SecurityMode modeOf(SecurityOwnershipMode ownership) {
        return ownership == SecurityOwnershipMode.CONTEXA_OWNED ? SecurityMode.FULL : SecurityMode.SANDBOX;
    }

    private static ContexaOperatingProfileException disagreement(SecurityMode mode, SecurityOwnershipMode ownership) {
        if (mode == SecurityMode.FULL) {
            return new ContexaOperatingProfileException(
                    "@EnableAISecurity(mode = FULL) means Contexa owns the sign-in, but " + PROP_OWNERSHIP + "=" + ownership
                            + " says the application keeps it.",
                    "Remove " + PROP_OWNERSHIP + ", or, for an application that keeps its sign-in, use @EnableAISecurity without mode = FULL.");
        }
        return new ContexaOperatingProfileException(
                "@EnableAISecurity in mode SANDBOX means the application keeps its sign-in, but " + PROP_OWNERSHIP + "=" + ownership
                        + " says Contexa owns it.",
                "Remove " + PROP_OWNERSHIP + ", or, for a new application whose sign-in Contexa owns, use @EnableAISecurity(mode = FULL).");
    }

    /**
     * What the application declares always stands: an application without a database of its own may say so in any mode. Left
     * alone, an application whose sign-in Contexa owns uses Contexa's database unless it has one of its own, which is never
     * replaced behind its back.
     */
    private static boolean applicationData(SecurityOwnershipMode ownership, Environment environment) {
        String declared = environment.getProperty(PROP_APPLICATION_DATA);
        if (StringUtils.hasText(declared)) {
            return Boolean.parseBoolean(declared.trim());
        }
        if (ownership != SecurityOwnershipMode.CONTEXA_OWNED) {
            return false;
        }
        return sameDatabaseOrNone(environment);
    }

    private static boolean sameDatabaseOrNone(Environment environment) {
        String application = environment.getProperty("spring.datasource.url");
        return !StringUtils.hasText(application) || application.trim().equals(trimmed(environment.getProperty("contexa.datasource.url")));
    }

    private static String trimmed(@Nullable String value) {
        return value == null ? "" : value.trim();
    }

    /** Read as Spring binds an enum, so no spelling that binds means something else here. */
    @Nullable
    private static <E extends Enum<E>> E read(Environment environment, String name, Class<E> type) {
        String value = environment.getProperty(name);
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String wanted = lettersOf(value);
        for (E constant : type.getEnumConstants()) {
            if (lettersOf(constant.name()).equals(wanted)) {
                return constant;
            }
        }
        String choices = Arrays.stream(type.getEnumConstants()).map(Enum::name).collect(Collectors.joining(", "));
        throw new ContexaOperatingProfileException(name + "=" + value.trim() + " is none of " + choices + ".", "Use one of: " + choices + ".");
    }

    private static String lettersOf(String value) {
        return value.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
    }
}
