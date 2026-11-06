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
package io.contexa.contexacommon.security.subject;

/**
 * An {@link AgentClientDirectory} could not tell whether a client is a suspended agent: its store failed or did not
 * answer in time. A suspension is a restriction, and a restriction is never lifted by a failure, so whoever asked
 * stops what the client would do for now (a token is neither issued nor accepted) instead of reading the failure as
 * "not suspended". The exception carries no more than the client it is about; the cause stays in the log.
 */
public class AgentClientStatusUnavailableException extends RuntimeException {

    public AgentClientStatusUnavailableException(String message) {
        super(message);
    }

    public AgentClientStatusUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
