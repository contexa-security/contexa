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
package io.contexa.contexacommon.security.bridge.subject;

/**
 * Why the user an application named for Contexa, or the way Contexa found it, falls short of the legacy integration
 * standard. A problem never fails the application's request: the request goes on, and Contexa counts and reports it.
 */
public enum SubjectProblem {

    /** No user id, or one of blanks only: the request has no Contexa identity. */
    USER_ID_BLANK,
    /** A user id longer than {@link ContexaSubject#MAX_TEXT_LENGTH}: the request has no Contexa identity. */
    USER_ID_TOO_LONG,
    /** A user id with a control character: the request has no Contexa identity. */
    USER_ID_CONTROL_CHARACTER,
    /** No mail address: the identity stands, but no verification code can be sent to it. */
    EMAIL_MISSING,
    /** A mail address that is no address: the identity stands, but no verification code can be sent to it. */
    EMAIL_MALFORMED,
    /** A mail address longer than {@link ContexaSubject#MAX_TEXT_LENGTH}: treated as missing. */
    EMAIL_TOO_LONG,
    /** A display name too long or with a control character, left out. */
    DISPLAY_NAME_DROPPED,
    /** An organization id too long or with a control character, left out. */
    ORGANIZATION_DROPPED,
    /** A tenant id too long or with a control character, left out. */
    TENANT_DROPPED,
    /** A session key too long or with a control character, left out. */
    SESSION_KEY_DROPPED,
    /** Authorities beyond {@link ContexaSubject#MAX_AUTHORITIES}, too long or with a control character, left out. */
    AUTHORITIES_TRIMMED,
    /** An authentication method or assurance too long or with a control character, left out. */
    AUTHENTICATION_FIELD_DROPPED,
    /** A delegation that names no agent, left out. */
    DELEGATION_DROPPED,
    /**
     * A signed-in Spring Security principal of none of the kinds Spring Security names a user by: Contexa does not read
     * its fields, and a {@link ContexaSubjectMapper} has to name the user.
     */
    UNSUPPORTED_PRINCIPAL,
    /** The application's {@link ContexaSubjectMapper} failed. */
    MAPPER_FAILED,
    /** The application's {@link ContexaSubjectResolver} failed. */
    RESOLVER_FAILED,
    /** The application's {@link ContexaSubjectResolver} took longer than the threshold it is measured against. */
    RESOLVER_SLOW,
    /** The application's mail address provider failed. */
    EMAIL_PROVIDER_FAILED,
    /** Two sources of one request named two different users: Contexa took the first in its order. */
    SOURCES_DISAGREE,
    /** The request attribute {@link ContexaSubject#REQUEST_ATTRIBUTE} holds something that is no {@link ContexaSubject}. */
    NOT_A_SUBJECT;

    /** Whether the problem leaves the request without a Contexa identity. */
    public boolean breaksTheUserId() {
        return this == USER_ID_BLANK || this == USER_ID_TOO_LONG || this == USER_ID_CONTROL_CHARACTER;
    }

    /** Whether the problem leaves the identity without a mail address. */
    public boolean breaksTheEmail() {
        return this == EMAIL_MISSING || this == EMAIL_MALFORMED || this == EMAIL_TOO_LONG;
    }
}
