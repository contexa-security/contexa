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
package io.contexa.contexaiam.admin.web.auth.service;

import org.springframework.security.access.AccessDeniedException;

/**
 * A change asked for by a session that stands under its own BLOCK. The session reads the block list and its pages offer
 * it nothing to change, so this answer is a plain 403. Its own release refused for want of a verification is not this:
 * that one is an {@link AccessDeniedException} the session reads on the page it came from.
 */
public class UnderOwnBlockException extends AccessDeniedException {

    private static final long serialVersionUID = 1L;

    public UnderOwnBlockException(String message) {
        super(message);
    }
}
