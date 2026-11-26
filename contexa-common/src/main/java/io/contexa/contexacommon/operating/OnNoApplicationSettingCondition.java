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

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.Map;

/** Reads the prefixes as Spring Boot binds its own settings, so that every spelling of a setting counts. */
class OnNoApplicationSettingCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        Map<String, Object> attributes = metadata.getAnnotationAttributes(ConditionalOnNoApplicationSetting.class.getName());
        String[] prefixes = (String[]) attributes.get("prefix");
        ConditionMessage.Builder message = ConditionMessage.forCondition(ConditionalOnNoApplicationSetting.class);
        Binder binder = Binder.get(context.getEnvironment());
        for (String prefix : prefixes) {
            boolean set = binder.bind(prefix, Bindable.mapOf(String.class, Object.class))
                    .map(settings -> !settings.isEmpty())
                    .orElse(false);
            if (set) {
                return ConditionOutcome.noMatch(message.because("the application sets " + prefix));
            }
        }
        return ConditionOutcome.match(message.because("the application sets none of " + String.join(", ", prefixes)));
    }
}
