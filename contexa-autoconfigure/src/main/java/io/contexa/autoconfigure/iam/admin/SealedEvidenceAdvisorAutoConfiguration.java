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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.verification.capture.SealedEvidenceAdvisors;
import io.contexa.contexacore.verification.capture.SealedEvidenceLayer1CompletionAspect;
import io.contexa.contexacore.verification.capture.SealedEvidenceLayer2CompletionAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptCaptureAspect;
import org.springframework.aop.Advisor;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;

/** The sealed evidence's advisors, for whichever configuration created its capture beans (OSS or enterprise). */
@AutoConfiguration
public class SealedEvidenceAdvisorAutoConfiguration {

    @Bean(name = "contexaSealedEvidencePromptCaptureAdvisor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor promptCaptureAdvisor(ListableBeanFactory beans, ObjectProvider<SealedEvidencePromptCaptureAspect> aspect) {
        return SealedEvidenceAdvisors.promptCapture(beans, aspect);
    }

    @Bean(name = "contexaSealedEvidenceLayer1CompletionAdvisor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor layer1CompletionAdvisor(ListableBeanFactory beans, ObjectProvider<SealedEvidenceLayer1CompletionAspect> aspect) {
        return SealedEvidenceAdvisors.layer1Completion(beans, aspect);
    }

    @Bean(name = "contexaSealedEvidenceLayer2CompletionAdvisor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor layer2CompletionAdvisor(ListableBeanFactory beans, ObjectProvider<SealedEvidenceLayer2CompletionAspect> aspect) {
        return SealedEvidenceAdvisors.layer2Completion(beans, aspect);
    }
}
