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
package io.contexa.contexacore.autonomous.signal;

/**
 * Sends Contexa's decisions out as risk level changes (docs/agent A5-8, CAEP): a host declares a bean to push them to
 * its identity provider or other receivers ({@link RiskSignal#caepClaims} gives the token's claims to sign). Every
 * declared emitter is called when a decision changes a subject's level; a failing one is logged and the others still
 * run. Without one nothing is sent.
 */
@FunctionalInterface
public interface RiskSignalEmitter {

    void emit(RiskSignal signal);
}
