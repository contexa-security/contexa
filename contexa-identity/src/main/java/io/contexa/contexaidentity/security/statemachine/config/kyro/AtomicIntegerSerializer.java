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