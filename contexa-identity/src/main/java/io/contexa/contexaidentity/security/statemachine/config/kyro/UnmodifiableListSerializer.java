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
