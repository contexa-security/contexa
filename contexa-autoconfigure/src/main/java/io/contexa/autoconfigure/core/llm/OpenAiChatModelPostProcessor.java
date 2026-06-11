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
/*
package io.contexa.autoconfigure.core.llm;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

@Slf4j
@Component
public class OpenAiChatModelPostProcessor implements BeanPostProcessor {

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean.getClass().getName().equals("org.springframework.ai.openai.OpenAiChatModel")) {
            log.info("Intercepted OpenAiChatModel bean: {}", beanName);
            try {
                Field defaultOptionsField = findField(bean.getClass(), "defaultOptions");
                if (defaultOptionsField != null) {
                    defaultOptionsField.setAccessible(true);
                    Object defaultOptions = defaultOptionsField.get(bean);
                    if (defaultOptions != null) {
                        log.info("Modifying defaultOptions of OpenAiChatModel: {}", defaultOptions);

                        Integer maxTokens = null;
                        Integer maxCompletionTokens = null;

                        // 1. Getter 메서드를 통해 값 조회 시도
                        try {
                            Method getMaxTokens = defaultOptions.getClass().getMethod("getMaxTokens");
                            Method getMaxCompletionTokens = defaultOptions.getClass().getMethod("getMaxCompletionTokens");
                            maxTokens = (Integer) getMaxTokens.invoke(defaultOptions);
                            maxCompletionTokens = (Integer) getMaxCompletionTokens.invoke(defaultOptions);
                        } catch (Exception e) {
                            // Getter 메서드가 없거나 실패 시 필드 직접 접근
                            Field maxTokensField = findField(defaultOptions.getClass(), "maxTokens");
                            Field maxCompletionTokensField = findField(defaultOptions.getClass(), "maxCompletionTokens");
                            if (maxTokensField != null) {
                                maxTokensField.setAccessible(true);
                                maxTokens = (Integer) maxTokensField.get(defaultOptions);
                            }
                            if (maxCompletionTokensField != null) {
                                maxCompletionTokensField.setAccessible(true);
                                maxCompletionTokens = (Integer) maxCompletionTokensField.get(defaultOptions);
                            }
                        }

                        log.info("Current defaultOptions - maxTokens: {}, maxCompletionTokens: {}", maxTokens, maxCompletionTokens);

                        if (maxTokens != null) {
                            Integer targetMaxCompletionTokens = maxCompletionTokens != null ? maxCompletionTokens : maxTokens;

                            // 2. Setter 메서드를 통해 값 변경 시도
                            boolean modified = false;
                            try {
                                Method setMaxTokens = defaultOptions.getClass().getMethod("setMaxTokens", Integer.class);
                                Method setMaxCompletionTokens = defaultOptions.getClass().getMethod("setMaxCompletionTokens", Integer.class);
                                setMaxTokens.invoke(defaultOptions, (Integer) null);
                                setMaxCompletionTokens.invoke(defaultOptions, targetMaxCompletionTokens);
                                log.info("Successfully modified OpenAiChatOptions via setters.");
                                modified = true;
                            } catch (Exception ignored) {
                            }

                            // 3. Setter 실패 시 필드 직접 수정 시도
                            if (!modified) {
                                try {
                                    Field maxTokensField = findField(defaultOptions.getClass(), "maxTokens");
                                    Field maxCompletionTokensField = findField(defaultOptions.getClass(), "maxCompletionTokens");
                                    if (maxTokensField != null && maxCompletionTokensField != null) {
                                        maxTokensField.setAccessible(true);
                                        maxCompletionTokensField.setAccessible(true);
                                        maxTokensField.set(defaultOptions, null);
                                        maxCompletionTokensField.set(defaultOptions, targetMaxCompletionTokens);
                                        log.info("Successfully modified OpenAiChatOptions via reflection fields.");
                                        modified = true;
                                    }
                                } catch (Exception ignored) {
                                }
                            }

                            // 4. 객체 자체를 복사해서 새로 할당해야 하는 경우 (Immutable인 경우)
                            if (!modified) {
                                try {
                                    Method copyMethod = defaultOptions.getClass().getMethod("copy");
                                    Object copy = copyMethod.invoke(defaultOptions);

                                    Method setMaxTokens = copy.getClass().getMethod("setMaxTokens", Integer.class);
                                    Method setMaxCompletionTokens = copy.getClass().getMethod("setMaxCompletionTokens", Integer.class);
                                    setMaxTokens.invoke(copy, (Integer) null);
                                    setMaxCompletionTokens.invoke(copy, targetMaxCompletionTokens);

                                    defaultOptionsField.set(bean, copy);
                                    log.info("Successfully modified and replaced immutable OpenAiChatOptions copy.");
                                } catch (Exception e) {
                                    log.error("Failed to apply options modification using copy-fallback", e);
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Failed to post-process OpenAiChatModel for reasoning models", e);
            }
        }
        return bean;
    }

    private Field findField(Class<?> clazz, String name) {
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        return null;
    }
}
*/
