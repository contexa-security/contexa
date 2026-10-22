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

/** Where an agent stands in its life cycle (A1-6, AG-11f). */
public enum AgentStatus {

    /** In service. */
    ACTIVE,
    /** Stopped by a decision or an operator; it may be resumed. */
    SUSPENDED,
    /** Removed by its identity provider; a request it still makes is a fact the decision weighs. */
    DEREGISTERED
}
