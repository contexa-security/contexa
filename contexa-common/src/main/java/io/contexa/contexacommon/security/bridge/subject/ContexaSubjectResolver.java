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

import java.util.Optional;

/**
 * How an application that signs its users in without Spring Security names the user of a request for Contexa: one bean
 * of this type, which the application implements from its own sign-in state (a session object, its own token's
 * verification, the container's user, a header its own code verified).
 * <ul>
 *   <li>Contexa calls it once a request, after every servlet filter of the application, and reuses the answer for the
 *       forwards, includes, asynchronous and error dispatches of that request.</li>
 *   <li>It is given a read-only view of the request ({@link ContexaRequestView}): no body, no parameters, no session
 *       created.</li>
 *   <li>An empty answer is a request nobody signed in to; after the application's sign-out it simply answers empty, and
 *       Contexa keeps nothing in the application's session.</li>
 *   <li>A failure is caught: the request goes on without a Contexa identity, and Contexa reports it. The time it takes
 *       is measured and reported when it is long.</li>
 * </ul>
 * Two beans of this type stop the start: Contexa would not know which one names the user.
 */
@FunctionalInterface
public interface ContexaSubjectResolver {

    /** The signed-in user of the request, or empty when the request has none. */
    Optional<ContexaSubject> resolve(ContexaRequestView request);
}
