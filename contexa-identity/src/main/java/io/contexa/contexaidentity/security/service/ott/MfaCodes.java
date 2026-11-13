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
package io.contexa.contexaidentity.security.service.ott;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * The six-digit codes of an MFA step. Six digits are few, so a code is kept under its user: the stored key is made of the
 * user and the code, and a code is looked up only with the user of the MFA step that asks. A code of another user is then
 * neither found nor taken, two users may hold the same digits, and the attempts of a step are limited by the step. A sign-in
 * where the code is all there is (no user known when it is entered, no limit of attempts) keeps a long code.
 */
public final class MfaCodes {

    /** The digits of a code. */
    public static final int DIGITS = 6;

    private static final Pattern CODE = Pattern.compile("\\d{" + DIGITS + "}");
    private static final SecureRandom RANDOM = new SecureRandom();

    private MfaCodes() {
    }

    /** A new code, every digit equally likely. */
    static String newCode() {
        return String.format("%0" + DIGITS + "d", RANDOM.nextInt((int) Math.pow(10, DIGITS)));
    }

    /** Whether what a person entered has the form of a code. */
    static boolean isCode(String entered) {
        return entered != null && CODE.matcher(entered.trim()).matches();
    }

    /** The key a code is stored under: 36 characters, as the store's key column takes, the same for the same user and code. */
    static String keyOf(String username, String code) {
        return UUID.nameUUIDFromBytes(("contexa-mfa-code\u0000" + username + "\u0000" + code.trim())
                .getBytes(StandardCharsets.UTF_8)).toString();
    }
}
