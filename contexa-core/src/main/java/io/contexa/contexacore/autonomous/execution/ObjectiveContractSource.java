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
package io.contexa.contexacore.autonomous.execution;

import java.util.List;

/**
 * The business objectives an application declares in code (A2-1), beside the ones it writes in
 * {@code contexa.security.zerotrust.agent.objective-contracts}. A delegation that names one of these objective families
 * is compared with its contract: the operations and resource families of the application's {@code @Protectable}
 * methods it needs, and the most items one export may carry. Every bean of this type is read once, when the catalog
 * is built.
 */
@FunctionalInterface
public interface ObjectiveContractSource {

    List<ObjectiveResourceCompatibilityCatalog.ObjectiveContractDefinition> objectiveContracts();
}
