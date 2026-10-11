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
package io.contexa.contexacommon.security.bridge;

import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * One vocabulary for login methods: the names the platform records for a login and the authentication method
 * references (RFC 8176 {@code amr}) that carry them in a token. The identity module writes them and the bridge reads
 * them back from a session or a token.
 */
public final class AuthenticationMethodReferences {

    public static final String PASSWORD = "PASSWORD";
    public static final String ONE_TIME_CODE = "ONE_TIME_CODE";
    public static final String RECOVERY_CODE = "RECOVERY_CODE";
    public static final String PASSKEY = "PASSKEY";
    public static final String BIOMETRIC = "BIOMETRIC";

    /** Assurance of a login with one method. */
    public static final String SINGLE_FACTOR_ASSURANCE = "AAL1";
    /** Assurance of a login with two or more different methods. */
    public static final String MULTI_FACTOR_ASSURANCE = "AAL2";

    /** RFC 8176 value stating that more than one method was used. */
    public static final String MULTIPLE_FACTOR_REFERENCE = "mfa";

    private static final String METHOD_SEPARATOR = "+";

    /** One order for the methods of a login, so that the same login always has the same name and references. */
    private static final List<String> METHOD_ORDER = List.of(PASSWORD, PASSKEY, BIOMETRIC, ONE_TIME_CODE, RECOVERY_CODE);

    private AuthenticationMethodReferences() {
    }

    /** The {@code amr} value of a login method, or null when the method has none. */
    @Nullable
    public static String referenceOf(@Nullable String method) {
        if (method == null) {
            return null;
        }
        return switch (method) {
            case PASSWORD -> "pwd";
            case ONE_TIME_CODE, RECOVERY_CODE -> "otp";
            case PASSKEY -> "pop";
            default -> null;
        };
    }

    /** The login method of one {@code amr} value, or null when the value names no method. */
    @Nullable
    public static String methodOf(@Nullable String reference) {
        if (reference == null) {
            return null;
        }
        return switch (reference.trim().toLowerCase(Locale.ROOT)) {
            case "pwd" -> PASSWORD;
            case "otp", "sms", "tel" -> ONE_TIME_CODE;
            case "pop", "hwk", "swk" -> PASSKEY;
            case "face", "fpt", "iris", "retina", "vbm" -> BIOMETRIC;
            default -> null;
        };
    }

    /** The {@code amr} values of the methods of one login, with {@code mfa} when there are two or more. */
    public static List<String> referencesOf(Collection<String> methods) {
        LinkedHashSet<String> references = new LinkedHashSet<>();
        for (String method : distinctMethods(methods)) {
            String reference = referenceOf(method);
            if (reference != null) {
                references.add(reference);
            }
        }
        if (distinctMethods(methods).size() >= 2) {
            references.add(MULTIPLE_FACTOR_REFERENCE);
        }
        return List.copyOf(references);
    }

    /** The login methods named by {@code amr} values, in the method order and without repeats. */
    public static List<String> methodsOf(@Nullable Collection<String> references) {
        List<String> methods = new ArrayList<>();
        if (references == null) {
            return methods;
        }
        for (String reference : references) {
            methods.add(methodOf(reference));
        }
        return distinctMethods(methods);
    }

    /** The recorded name of a login made of the given methods, for example {@code PASSWORD+ONE_TIME_CODE}. */
    @Nullable
    public static String methodName(Collection<String> methods) {
        List<String> distinct = distinctMethods(methods);
        return distinct.isEmpty() ? null : String.join(METHOD_SEPARATOR, distinct);
    }

    /**
     * Whether {@code amr} values state a multi-factor login: {@code mfa}, or two or more different methods. Null when
     * there are no values.
     */
    @Nullable
    public static Boolean multiFactor(@Nullable Collection<String> references) {
        if (references == null || references.isEmpty()) {
            return null;
        }
        boolean declared = references.stream()
                .anyMatch(reference -> MULTIPLE_FACTOR_REFERENCE.equalsIgnoreCase(reference == null ? null : reference.trim()));
        return declared || methodsOf(references).size() >= 2;
    }

    /** The assurance of a login made of the given methods: AAL2 for two or more different methods, else AAL1. */
    public static String assuranceOf(Collection<String> methods) {
        return distinctMethods(methods).size() >= 2 ? MULTI_FACTOR_ASSURANCE : SINGLE_FACTOR_ASSURANCE;
    }

    private static List<String> distinctMethods(Collection<String> methods) {
        List<String> distinct = new ArrayList<>();
        for (String method : methods) {
            if (method != null && !method.isBlank() && !distinct.contains(method)) {
                distinct.add(method);
            }
        }
        distinct.sort(Comparator.comparingInt(AuthenticationMethodReferences::orderOf));
        return distinct;
    }

    private static int orderOf(String method) {
        int index = METHOD_ORDER.indexOf(method);
        return index >= 0 ? index : METHOD_ORDER.size();
    }
}
