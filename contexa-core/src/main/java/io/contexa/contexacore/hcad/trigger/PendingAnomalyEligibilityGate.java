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
package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionRequestResolver;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

public class PendingAnomalyEligibilityGate {
    private final ZeroTrustActionRepository actionRepository;
    private final AnalysisTriggerStateRepository analysisTriggerStateRepository;
    private final HcadProperties hcadProperties;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public PendingAnomalyEligibilityGate(
            ZeroTrustActionRepository actionRepository,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            HcadProperties hcadProperties) {
        this.actionRepository = actionRepository;
        this.analysisTriggerStateRepository = analysisTriggerStateRepository;
        this.hcadProperties = hcadProperties;
    }

    public PendingAnomalyEligibility evaluate(HttpServletRequest request, Authentication authentication) {
        if (request == null || !trustResolver.isAuthenticated(authentication) || !hcadProperties.getPreTrigger().shouldEvaluate()) {
            return null;
        }

        HcadPreProtectablePromotionAssessment assessment = HcadPreProtectablePromotionRequestResolver.resolve(request);
        if (assessment.rawSignalSnapshot().isEmpty()) {
            return null;
        }

        String userId = firstText(
                assessment.rawSignalSnapshot().get("userId"),
                authentication.getName());
        if (!StringUtils.hasText(userId)) {
            return null;
        }

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        ZeroTrustAction currentAction = actionRepository.getCurrentAction(userId, contextBindingHash);
        if (currentAction == ZeroTrustAction.CHALLENGE || currentAction == ZeroTrustAction.BLOCK) {
            return null;
        }

        String baseKey = PendingAnomalyKeyFactory.buildBaseKey(
                userId,
                contextBindingHash,
                request.getMethod(),
                HcadRequestPathUtils.normalizedPath(request));

        if (analysisTriggerStateRepository.isNegativeCached(baseKey)) {
            return null;
        }
        return new PendingAnomalyEligibility(userId, contextBindingHash, baseKey);
    }

    private String firstText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString();
            if (StringUtils.hasText(text)) {
                return text.trim();
            }
        }
        return null;
    }
}
