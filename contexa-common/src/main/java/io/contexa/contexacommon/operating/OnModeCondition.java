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
package io.contexa.contexacommon.operating;

import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

import java.util.Map;

/** Asked as early as a property condition, as {@link OnOwnershipCondition} is. */
@Order(Ordered.HIGHEST_PRECEDENCE + 40)
class OnModeCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        Map<String, Object> attributes = metadata.getAnnotationAttributes(ConditionalOnMode.class.getName());
        SecurityMode wanted = (SecurityMode) attributes.get("value");
        ConditionMessage.Builder message = ConditionMessage.forCondition(ConditionalOnMode.class, wanted);
        // An application that sets only the ownership declares a way of running Contexa too: the profile reads its mode from it
        if (!StringUtils.hasText(context.getEnvironment().getProperty(ContexaOperatingProfile.PROP_MODE))
                && ContexaOperatingProfile.ownershipUndeclared(context.getEnvironment())) {
            return Boolean.TRUE.equals(attributes.get("matchIfUndeclared"))
                    ? ConditionOutcome.match(message.because("no mode is declared"))
                    : ConditionOutcome.noMatch(message.because("no mode is declared"));
        }
        SecurityMode mode = ContexaOperatingProfile.resolve(context.getEnvironment()).mode();
        return mode == wanted
                ? ConditionOutcome.match(message.because("the mode is " + mode))
                : ConditionOutcome.noMatch(message.because("the mode is " + mode));
    }
}
