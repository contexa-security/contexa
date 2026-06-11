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

import java.util.concurrent.atomic.AtomicInteger;

public class AtomicIntegerSerializer extends Serializer<AtomicInteger> {
    @Override
    public void write(Kryo kryo, Output output, AtomicInteger value) {
        kryo.writeClassAndObject(output, value.get()); 
    }

    @Override
    public AtomicInteger read(Kryo kryo, Input input, Class<? extends AtomicInteger> type) {
        int value = (int)kryo.readClassAndObject(input); 
        return new AtomicInteger(value);
    }
}