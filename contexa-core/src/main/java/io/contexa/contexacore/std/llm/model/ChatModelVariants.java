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
package io.contexa.contexacore.std.llm.model;

import io.contexa.contexacore.std.llm.client.ChatModelProviders;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Optional;

/**
 * A chat model of another model id made from a configured one: the same provider, client and default options, only the
 * model differs. Spring AI chat models that copy themselves through {@code mutate()} with
 * {@code defaultOptions(...)} (OpenAI) give one; Anthropic has no {@code mutate()} and is built again through its public
 * {@code builder()} from what the model holds; any other gives none. A copy has default options of its own because a
 * request cannot take a default out: Spring AI merges the defaults back into what a request leaves out, and a model
 * that refuses a default sampling value answers 400. The provider classes are reached by reflection, as the options
 * factory does, so the core needs no provider at compile time.
 */
@Slf4j
public final class ChatModelVariants {

    private ChatModelVariants() {
    }

    public static Optional<ChatModel> withModel(ChatModel base, String modelId) {
        if (base == null || modelId == null || modelId.isBlank()) {
            return Optional.empty();
        }
        try {
            ChatOptions defaults = base.getDefaultOptions();
            if (defaults == null) {
                return Optional.empty();
            }
            ChatOptions options = defaults.copy();
            Method setModel = options.getClass().getMethod("setModel", String.class);
            setModel.invoke(options, modelId.trim());
            Object builder = builderOf(base);
            Method defaultOptions = singleArgument(builder.getClass(), "defaultOptions", options.getClass());
            if (defaultOptions == null) {
                return Optional.empty();
            }
            defaultOptions.invoke(builder, options);
            Object built = builder.getClass().getMethod("build").invoke(builder);
            return built instanceof ChatModel model ? Optional.of(model) : Optional.empty();
        } catch (NoSuchMethodException e) {
            return Optional.empty();
        } catch (ReflectiveOperationException | RuntimeException e) {
            log.error("[ChatModelVariants] A chat model of model {} could not be made from {}", modelId,
                    base.getClass().getSimpleName(), e);
            return Optional.empty();
        }
    }

    /** The builder of a copy of the model: its own, or an Anthropic model's class's, given what the model holds. */
    private static Object builderOf(ChatModel base) throws ReflectiveOperationException {
        try {
            return base.getClass().getMethod("mutate").invoke(base);
        } catch (NoSuchMethodException e) {
            if (!"anthropic".equals(ChatModelProviders.providerOf(base))) {
                throw e;
            }
        }
        Object builder = base.getClass().getMethod("builder").invoke(null);
        for (Method setter : builder.getClass().getMethods()) {
            if (setter.getParameterCount() == 1) {
                handOver(base, builder, setter);
            }
        }
        return builder;
    }

    /** Gives the builder what the model holds under the setter's name. */
    private static void handOver(ChatModel base, Object builder, Method setter) throws ReflectiveOperationException {
        Field field = ReflectionUtils.findField(base.getClass(), setter.getName());
        if (field == null || Modifier.isStatic(field.getModifiers())) {
            return;
        }
        ReflectionUtils.makeAccessible(field);
        Object held = field.get(base);
        if (setter.getParameterTypes()[0].isInstance(held)) {
            setter.invoke(builder, held);
        }
    }

    private static Method singleArgument(Class<?> type, String name, Class<?> argument) {
        for (Method method : type.getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == 1
                    && method.getParameterTypes()[0].isAssignableFrom(argument)) {
                return method;
            }
        }
        return null;
    }
}
