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

import org.springframework.security.core.Authentication;

import java.util.Optional;

/**
 * How an application that signs its users in with Spring Security names the user of an authentication of its own kind
 * for Contexa: one bean of this type. Contexa reads the standard kinds itself (a user's details, a principal, a text, an
 * OAuth2 token or login) and never the fields of an application's own principal object; for such a principal, the
 * application maps it.
 * <pre>
 * authentication -&gt; authentication.getPrincipal() instanceof MyLoginUser user
 *         ? Optional.of(ContexaSubject.of(user.getEmpNo(), user.getMail()).build())
 *         : Optional.empty();
 * </pre>
 * An empty answer leaves the authentication to Contexa's reading of the standard kinds. A failure is caught and reported,
 * and the request goes on. Two beans of this type stop the start.
 */
@FunctionalInterface
public interface ContexaSubjectMapper {

    /** The user of a signed-in authentication, or empty to let Contexa read it as a standard kind. */
    Optional<ContexaSubject> map(Authentication authentication);
}
