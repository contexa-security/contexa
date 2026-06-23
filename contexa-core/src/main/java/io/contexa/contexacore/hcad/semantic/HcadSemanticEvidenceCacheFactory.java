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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.properties.HcadProperties;
import org.springframework.data.redis.core.StringRedisTemplate;

public final class HcadSemanticEvidenceCacheFactory {

    private HcadSemanticEvidenceCacheFactory() {
    }

    public static HcadSemanticEvidenceCache create(
            String infrastructureMode,
            HcadProperties hcadProperties,
            StringRedisTemplate stringRedisTemplate,
            ObjectMapper objectMapper) {
        HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider provider =
                hcadProperties.getSemanticEvidence().getProvider();
        if (!hcadProperties.getSemanticEvidence().isEnabled()
                || provider == HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.DISABLED) {
            return new DisabledHcadSemanticEvidenceCache("SEMANTIC_EVIDENCE_DISABLED");
        }
        boolean distributed = "distributed".equalsIgnoreCase(infrastructureMode);
        if (distributed) {
            if (provider == HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.CAFFEINE) {
                return new DisabledHcadSemanticEvidenceCache("CAFFEINE_NOT_ALLOWED_FOR_DISTRIBUTED_SEMANTIC_EVIDENCE");
            }
            if (stringRedisTemplate == null) {
                return new DisabledHcadSemanticEvidenceCache("REDIS_REQUIRED_FOR_DISTRIBUTED_SEMANTIC_EVIDENCE");
            }
            return new RedisHcadSemanticEvidenceCache(stringRedisTemplate, objectMapper, hcadProperties);
        }
        if (provider == HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.REDIS) {
            return new DisabledHcadSemanticEvidenceCache("REDIS_NOT_ALLOWED_FOR_LOCAL_SEMANTIC_EVIDENCE");
        }
        return new CaffeineHcadSemanticEvidenceCache(hcadProperties);
    }
}
