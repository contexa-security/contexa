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

import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.Map;

/** Asked as early as a property condition, so that it keeps the place of the conditions it replaced. */
@Order(Ordered.HIGHEST_PRECEDENCE + 40)
class OnOwnershipCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        Map<String, Object> attributes = metadata.getAnnotationAttributes(ConditionalOnOwnership.class.getName());
        SecurityOwnershipMode wanted = (SecurityOwnershipMode) attributes.get("value");
        ConditionMessage.Builder message = ConditionMessage.forCondition(ConditionalOnOwnership.class, wanted);
        if (ContexaOperatingProfile.ownershipUndeclared(context.getEnvironment())) {
            return Boolean.TRUE.equals(attributes.get("matchIfUndeclared"))
                    ? ConditionOutcome.match(message.because("no ownership is declared"))
                    : ConditionOutcome.noMatch(message.because("no ownership is declared"));
        }
        SecurityOwnershipMode ownership = ContexaOperatingProfile.resolve(context.getEnvironment()).ownership();
        return ownership == wanted
                ? ConditionOutcome.match(message.because("the ownership is " + ownership))
                : ConditionOutcome.noMatch(message.because("the ownership is " + ownership));
    }
}
