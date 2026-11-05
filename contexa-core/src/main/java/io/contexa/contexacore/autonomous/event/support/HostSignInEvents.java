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
package io.contexa.contexacore.autonomous.event.support;

/**
 * Whether the sign-ins of the application reach Contexa (HOST_OWNED). Contexa hears of a failed sign-in only through the
 * events of the application's authentication manager, and a manager built by hand publishes none, so no failure on record
 * says nothing and a count of zero would tell the decisions that nobody failed. A manager publishes its successes and its
 * failures alike: one event of either kind shows that a failure would have arrived.
 */
public class HostSignInEvents {

    private volatile boolean reaching;

    /** An event of the application's authentication manager arrived. */
    public void reached() {
        reaching = true;
    }

    public boolean reaching() {
        return reaching;
    }
}
