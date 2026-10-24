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
package io.contexa.contexacore.autonomous.agent;

/**
 * Delivers a notice to the person accountable for an agent (docs/agent A5-2, A5-3). The default sends mail through the
 * application's mail sender when it has one and the person's account names an address; declare a bean of this type to
 * deliver another way (chat, push, a ticket). The notice is kept for the console whatever the channel does.
 */
public interface AgentNoticeChannel {

    /**
     * Delivers the notice.
     *
     * @return the channel's name when it delivered the notice, or null when it could not (no sender, no address, a
     *         failure); the notice is then kept for the console alone
     */
    String deliver(AgentNotice notice);
}
