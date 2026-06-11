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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class UnmodifiableListSerializer extends Serializer<List<?>> {

    @Override
    public void write(Kryo kryo, Output output, List<?> object) {
        
        output.writeInt(object.size(), true);
        for (Object element : object) {
            kryo.writeClassAndObject(output, element);
        }
    }

    @Override
    @SuppressWarnings({"rawtypes"})
    public List<?> read(Kryo kryo, Input input, Class<? extends List<?>> type) {
        int size = input.readInt(true);
        ArrayList<Object> list = new ArrayList<>(size); 
        for (int i = 0; i < size; i++) {
            list.add(kryo.readClassAndObject(input));
        }

        return Collections.unmodifiableList(list);
    }
}
