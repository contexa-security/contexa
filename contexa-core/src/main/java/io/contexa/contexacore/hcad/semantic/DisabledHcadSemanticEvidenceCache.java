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
package io.contexa.contexacore.hcad.semantic;

import io.contexa.contexacore.properties.HcadProperties;

import java.time.Duration;
import java.util.Optional;

public class DisabledHcadSemanticEvidenceCache implements HcadSemanticEvidenceCache {

    private final String reason;

    public DisabledHcadSemanticEvidenceCache(String reason) {
        this.reason = reason == null || reason.isBlank() ? "DISABLED" : reason;
    }

    @Override
    public Optional<HcadSemanticEvidenceEntry> get(HcadSemanticEvidenceKey key) {
        return Optional.empty();
    }

    @Override
    public void put(HcadSemanticEvidenceEntry entry, Duration ttl) {
    }

    @Override
    public void putSourceAbsent(HcadSemanticEvidenceKey key, Duration ttl) {
    }

    @Override
    public boolean isSourceAbsent(HcadSemanticEvidenceKey key) {
        return false;
    }

    @Override
    public void invalidate(HcadSemanticEvidenceKey key) {
    }

    @Override
    public HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider provider() {
        return HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.DISABLED;
    }

    public String reason() {
        return reason;
    }
}
