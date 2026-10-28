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
package io.contexa.contexacommon.annotation;

/**
 * How the host classifies a protected resource for the engine's handling of requests that come in numbers
 * ({@link Protectable#importance()}). The host states it on the resource itself; the engine does not infer it from the
 * kind of operation (a read can be sensitive and a write can be harmless).
 */
public enum ResourceImportance {

    /**
     * The host declares nothing. The engine reads the sensitivity words the resource or the request carries, as it did
     * before, and treats the resource as one that may not be let through before its verdict.
     */
    UNSPECIFIED,

    /**
     * The host declares the resource not sensitive. Only such a resource is a candidate for a few requests passing
     * while the first one is still being decided. A request-level sensitivity the host states can still raise it.
     */
    NON_SENSITIVE,

    /**
     * The host declares the resource sensitive. Each such resource is decided on its own, its ALLOW answers no other
     * resource, and the request is checked against the restrictions in force again right before it runs. The host
     * cannot lower it.
     */
    SENSITIVE
}
