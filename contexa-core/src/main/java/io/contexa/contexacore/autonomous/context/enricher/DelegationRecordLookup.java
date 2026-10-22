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
package io.contexa.contexacore.autonomous.context.enricher;

import java.util.Optional;

/**
 * Finds the delegation a request runs under in the host's business records (A1-4, AG-1e). Declare one as a bean and
 * Contexa registers a {@link RecordedDelegationContextProvider} that applies the record to every agent request.
 *
 * <p>It is called on the analysis thread, once for each request that names an agent or a delegation, never for a
 * person's own requests. Return {@link Optional#empty()} when no record matches; a thrown exception is recorded as a
 * failed lookup and the decision continues with the delegation the request stated.
 */
@FunctionalInterface
public interface DelegationRecordLookup {

    Optional<DelegationRecord> find(DelegationRecordQuery query);
}
