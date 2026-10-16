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
package io.contexa.contexacore.verification.evidence;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;

import java.util.Objects;
import java.util.function.BiConsumer;

/**
 * W6-9 (P6-CHANGE-6): seals a shadow run as its own package (its own correlation id, the SHADOW stage), from the prompt
 * trace its copy left, as the capture handler seals a decision.
 */
public class SealedEvidenceShadowSealer implements BiConsumer<SecurityEvent, ProcessingResult> {

    private final SealedEvidencePackageAssembler assembler;
    private final SealedEvidencePackageRepository repository;

    public SealedEvidenceShadowSealer(SealedEvidencePackageAssembler assembler,
                                      SealedEvidencePackageRepository repository) {
        this.assembler = Objects.requireNonNull(assembler, "assembler");
        this.repository = Objects.requireNonNull(repository, "repository");
    }

    @Override
    public void accept(SecurityEvent copy, ProcessingResult result) {
        SecurityEventContext context = new SecurityEventContext(copy);
        context.getMetadata().put("processingResult", result);
        SealedEvidencePackage sealed = assembler.assemble(context);
        if (sealed != null) {
            repository.save(sealed);
        }
    }
}
