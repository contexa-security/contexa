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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The read-only views of {@link Collections} over a map, sorted ones included: the entries are kept in their order and
 * the view is made again, as a plain map view.
 */
public class UnmodifiableMapSerializer extends Serializer<Map<?, ?>> {

    @Override
    public void write(Kryo kryo, Output output, Map<?, ?> object) {
        output.writeInt(object.size(), true);
        for (Map.Entry<?, ?> entry : object.entrySet()) {
            kryo.writeClassAndObject(output, entry.getKey());
            kryo.writeClassAndObject(output, entry.getValue());
        }
    }

    @Override
    public Map<?, ?> read(Kryo kryo, Input input, Class<? extends Map<?, ?>> type) {
        int size = input.readInt(true);
        Map<Object, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < size; i++) {
            Object key = kryo.readClassAndObject(input);
            map.put(key, kryo.readClassAndObject(input));
        }
        return Collections.unmodifiableMap(map);
    }
}
