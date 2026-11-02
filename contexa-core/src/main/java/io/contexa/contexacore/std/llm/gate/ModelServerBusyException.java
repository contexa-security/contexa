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
package io.contexa.contexacore.std.llm.gate;

/**
 * A call that found no free slot at its model server within the wait it had (what is left of the event's budget). It
 * is a defined outcome, recorded as MODEL_SERVER_BUSY, not a failure of the server.
 */
public class ModelServerBusyException extends RuntimeException {

    /** The failure category a call that ended here is recorded with. */
    public static final String FAILURE_CATEGORY = "MODEL_SERVER_BUSY";

    private final String server;

    public ModelServerBusyException(String server, String message) {
        super(message);
        this.server = server;
    }

    public String getServer() {
        return server;
    }
}
