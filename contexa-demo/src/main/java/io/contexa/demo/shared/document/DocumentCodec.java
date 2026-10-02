package io.contexa.demo.shared.document;

public interface DocumentCodec {

    String write(Object value);

    <T> T read(String value, Class<T> type);

    String hash(String value);

    String hash(byte[] value);
}
