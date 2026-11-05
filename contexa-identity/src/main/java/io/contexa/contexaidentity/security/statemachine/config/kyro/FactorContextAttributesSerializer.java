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
package io.contexa.contexaidentity.security.statemachine.config.kyro;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import lombok.extern.slf4j.Slf4j;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The attributes of a stored MFA flow, each on its own. An attribute may hold a value of the application (the metadata
 * of its policy), so one that cannot be written or read back is left out, with an error in the log, and the rest of the
 * flow stays. Contexa's own attributes are plain values and collections of them, which read back on any node. A value
 * has its own bytes and its own Kryo, used only with the Kryo of the flow: a value that fails leaves nothing behind in
 * the flow's stream or in the class names it shares.
 */
@Slf4j
class FactorContextAttributesSerializer extends Serializer<Map<String, Object>> {

    private static final int INITIAL_VALUE_BUFFER = 256;

    private final Kryo values;

    FactorContextAttributesSerializer(Kryo values) {
        this.values = values;
    }

    @Override
    public void write(Kryo kryo, Output output, Map<String, Object> attributes) {
        Map<String, byte[]> encoded = new LinkedHashMap<>();
        attributes.forEach((name, value) -> {
            try {
                encoded.put(name, encode(value));
            } catch (RuntimeException | LinkageError | StackOverflowError e) {
                log.error("[MFA SM] Attribute {} ({}) cannot be stored and is left out of the flow: {}",
                        name, value.getClass().getName(), e.toString());
            }
        });

        output.writeInt(encoded.size(), true);
        encoded.forEach((name, value) -> {
            output.writeString(name);
            output.writeInt(value.length, true);
            output.writeBytes(value);
        });
    }

    @Override
    public Map<String, Object> read(Kryo kryo, Input input, Class<? extends Map<String, Object>> type) {
        int size = input.readInt(true);
        Map<String, Object> attributes = new ConcurrentHashMap<>();
        for (int i = 0; i < size; i++) {
            String name = input.readString();
            byte[] value = input.readBytes(input.readInt(true));
            try {
                attributes.put(name, decode(value));
            } catch (RuntimeException | LinkageError | StackOverflowError e) {
                log.error("[MFA SM] Attribute {} cannot be read back and is left out of the flow: {}", name, e.toString());
            }
        }
        return attributes;
    }

    private byte[] encode(Object value) {
        try (Output output = new Output(INITIAL_VALUE_BUFFER, -1)) {
            values.writeClassAndObject(output, value);
            return output.toBytes();
        }
    }

    private Object decode(byte[] value) {
        try (Input input = new Input(value)) {
            return values.readClassAndObject(input);
        }
    }
}
