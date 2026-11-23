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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;

import java.util.List;

/**
 * The checks the build runs over the golden inputs, in report order (plan 2.1 of the prompt quality redesign): the
 * seal integrity and the renderer's checks that read the prompt's lines (dictionary contract, decision facts, fact
 * accuracy, declared unknowns, past record notation, same fact) with the reason codes against the facts they cite.
 * The renderer is deterministic, so they run here, on what the render draws, and no longer on the sealed packages,
 * whose inspection is the evidence audit of {@link PromptInspector#coreChecks()}.
 */
public final class RendererInspectionChecks {

    private RendererInspectionChecks() {
    }

    /** The checks the sealed packages were inspected with before the evidence audit, in their report order. */
    public static List<PromptInspectionCheck> coreChecks() {
        return List.of(new SealIntegrityCheck(new SealedEvidencePackageIntegrity()), new DictionaryContractCheck(),
                new DecisionFactMatchCheck(), new FactAccuracyCheck(), new UnknownDeclaredCheck(),
                new PastRecordNotationCheck(), new SameFactCheck(), new ReasonMatchCheck());
    }
}
