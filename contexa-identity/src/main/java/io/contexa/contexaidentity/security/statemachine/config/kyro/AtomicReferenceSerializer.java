package io.contexa.contexaidentity.security.statemachine.config.kyro;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

import java.util.concurrent.atomic.AtomicReference;

public class AtomicReferenceSerializer extends Serializer<AtomicReference> {
    @Override
    public void write(Kryo kryo, Output output, AtomicReference object) {
        kryo.writeClassAndObject(output, object.get()); // 내부 값만 직렬화
    }

    @Override
    public AtomicReference read(Kryo kryo, Input input, Class<? extends AtomicReference> type) {
        Object value = kryo.readClassAndObject(input); // 내부 값 역직렬화
        return new AtomicReference(value);
    }
}