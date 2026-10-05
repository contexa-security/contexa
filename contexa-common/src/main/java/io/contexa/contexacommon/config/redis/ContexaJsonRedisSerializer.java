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
package io.contexa.contexacommon.config.redis;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;

/**
 * Jackson Redis serializer whose polymorphic type resolution is always governed by
 * {@link ContexaRedisTypeValidator}.
 *
 * <p>{@link GenericJackson2JsonRedisSerializer} resolves a root-level {@code @class} hint with
 * {@code TypeFactory#constructFromCanonical} before Jackson runs, which loads the named class and
 * skips the configured validator when that class is final. This serializer always reads untyped
 * requests as {@link Object} so that every type id goes through Jackson default typing and the
 * validator. The wire format written by the configured {@link ObjectMapper} is unchanged.</p>
 */
public class ContexaJsonRedisSerializer extends GenericJackson2JsonRedisSerializer {

    public ContexaJsonRedisSerializer(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    /**
     * Enables NON_FINAL default typing with the Contexa allowlist validator, keeping the
     * Jackson default WRAPPER_ARRAY inclusion used by existing Redis data.
     */
    public static ObjectMapper activateDefaultTyping(ObjectMapper objectMapper) {
        return objectMapper.activateDefaultTyping(
                ContexaRedisTypeValidator.instance(),
                ObjectMapper.DefaultTyping.NON_FINAL);
    }

    /**
     * Enables NON_FINAL default typing with the Contexa allowlist validator and the given inclusion.
     */
    public static ObjectMapper activateDefaultTyping(ObjectMapper objectMapper, JsonTypeInfo.As inclusion) {
        return objectMapper.activateDefaultTyping(
                ContexaRedisTypeValidator.instance(),
                ObjectMapper.DefaultTyping.NON_FINAL,
                inclusion);
    }

    @Override
    protected JavaType resolveType(byte[] source, Class<?> type) {
        return getObjectMapper().getTypeFactory().constructType(type);
    }
}
