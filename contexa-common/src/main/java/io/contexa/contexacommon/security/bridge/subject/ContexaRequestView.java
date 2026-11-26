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

import java.security.Principal;
import java.util.List;
import java.util.Optional;

/**
 * What a {@link ContexaSubjectResolver} may read of a request: a read-only view. It reads the session without creating
 * one, the headers, the cookies, the request attributes, the container's signed-in user and the path. It offers neither
 * the body nor the parameters, whose reading would consume a multipart or streamed body the application reads itself,
 * nor anything that changes the request.
 */
public interface ContexaRequestView {

    /** The HTTP method. */
    String method();

    /** The request URI as the client sent it, the context path included, not decoded. */
    String path();

    /** The first value of a header. */
    Optional<String> header(String name);

    /** Every value of a header, in order; empty when there is none. */
    List<String> headers(String name);

    /** The value of a cookie. */
    Optional<String> cookie(String name);

    /** A request attribute. */
    Optional<Object> attribute(String name);

    /** A request attribute of a type; empty when it is missing or of another type. */
    <T> Optional<T> attribute(String name, Class<T> type);

    /** An attribute of the request's session; empty when the request has no session, which is never created. */
    Optional<Object> sessionAttribute(String name);

    /** An attribute of the request's session of a type; empty when it is missing or of another type. */
    <T> Optional<T> sessionAttribute(String name, Class<T> type);

    /** The id of the request's session; empty when the request has none, which is never created. */
    Optional<String> sessionId();

    /** The user the servlet container signed in ({@code getRemoteUser()}). */
    Optional<String> remoteUser();

    /** The principal the servlet container signed in ({@code getUserPrincipal()}). */
    Optional<Principal> userPrincipal();
}
