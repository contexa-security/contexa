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
package io.contexa.contexaiam.aiam.protocol.request;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexacommon.domain.request.AIRequest;

public class PolicyGenerationRequest extends AIRequest<PolicyContext> {

    private PolicyGenerationItem.AvailableItems availableItems;

    public PolicyGenerationRequest(PolicyContext context, TemplateType templateType, DiagnosisType diagnosisType) {
        super(context, templateType, diagnosisType);
    }

    public PolicyGenerationItem.AvailableItems getAvailableItems() {
        return availableItems;
    }

    public void setAvailableItems(PolicyGenerationItem.AvailableItems availableItems) {
        this.availableItems = availableItems;
    }
}
