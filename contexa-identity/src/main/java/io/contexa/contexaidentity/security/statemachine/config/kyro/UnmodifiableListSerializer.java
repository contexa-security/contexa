package io.contexa.contexaidentity.security.statemachine.config.kyro;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

// UnmodifiableList (RandomAccess 포함)를 위한 시리얼라이저
public class UnmodifiableListSerializer extends Serializer<List<?>> {

    @Override
    public void write(Kryo kryo, Output output, List<?> object) {
        // 실제 내부 리스트의 크기와 내용을 쓴다.
        output.writeInt(object.size(), true);
        for (Object element : object) {
            kryo.writeClassAndObject(output, element);
        }
    }

    @Override
    @SuppressWarnings({"rawtypes"})
    public List<?> read(Kryo kryo, Input input, Class<? extends List<?>> type) {
        int size = input.readInt(true);
        ArrayList<Object> list = new ArrayList<>(size); // 내부적으로는 ArrayList로 복원
        for (int i = 0; i < size; i++) {
            list.add(kryo.readClassAndObject(input));
        }
        // 원래 타입이 UnmodifiableRandomAccessList 였다는 것을 안다면,
        // Collections.unmodifiableList(list)로 감싸서 반환할 수 있다.
        // 하지만 type 파라미터는 List<?>일 가능성이 높으므로,
        // 여기서는 그냥 ArrayList를 반환하거나, Collections.unmodifiableList()로 감싼다.
        return Collections.unmodifiableList(list);
    }
}
