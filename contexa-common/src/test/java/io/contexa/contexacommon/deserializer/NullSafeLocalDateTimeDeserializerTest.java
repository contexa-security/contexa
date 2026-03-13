package io.contexa.contexacommon.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NullSafeLocalDateTimeDeserializerTest {

    private NullSafeLocalDateTimeDeserializer deserializer;

    @Mock
    private JsonParser jsonParser;

    @Mock
    private DeserializationContext deserializationContext;

    @BeforeEach
    void setUp() {
        deserializer = new NullSafeLocalDateTimeDeserializer();
    }

    @Test
    @DisplayName("Deserialize null text returns null")
    void deserialize_shouldReturnNullForNullText() throws IOException {
        when(jsonParser.getText()).thenReturn(null);

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Deserialize empty string returns null")
    void deserialize_shouldReturnNullForEmptyString() throws IOException {
        when(jsonParser.getText()).thenReturn("");

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Deserialize whitespace-only string returns null")
    void deserialize_shouldReturnNullForWhitespaceString() throws IOException {
        when(jsonParser.getText()).thenReturn("   ");

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"None", "NONE", "none", "NoNe"})
    @DisplayName("Deserialize 'None' variants returns null (case-insensitive)")
    void deserialize_shouldReturnNullForNoneVariants(String value) throws IOException {
        when(jsonParser.getText()).thenReturn(value);

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "NULL", "Null"})
    @DisplayName("Deserialize 'null' variants returns null (case-insensitive)")
    void deserialize_shouldReturnNullForNullVariants(String value) throws IOException {
        when(jsonParser.getText()).thenReturn(value);

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"undefined", "UNDEFINED", "Undefined"})
    @DisplayName("Deserialize 'undefined' variants returns null (case-insensitive)")
    void deserialize_shouldReturnNullForUndefinedVariants(String value) throws IOException {
        when(jsonParser.getText()).thenReturn(value);

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Deserialize valid ISO date-time string returns correct LocalDateTime")
    void deserialize_shouldParseValidIsoDateTime() throws IOException {
        when(jsonParser.getText()).thenReturn("2025-01-01T00:00:00");

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isEqualTo(LocalDateTime.of(2025, 1, 1, 0, 0, 0));
    }

    @Test
    @DisplayName("Deserialize valid ISO date-time with fractional seconds")
    void deserialize_shouldParseIsoDateTimeWithFractionalSeconds() throws IOException {
        when(jsonParser.getText()).thenReturn("2025-06-15T14:30:45.123");

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isEqualTo(LocalDateTime.of(2025, 6, 15, 14, 30, 45, 123_000_000));
    }

    @Test
    @DisplayName("Deserialize invalid date format returns null")
    void deserialize_shouldReturnNullForInvalidDateFormat() throws IOException {
        when(jsonParser.getText()).thenReturn("invalid-date");

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Deserialize partially valid date returns null")
    void deserialize_shouldReturnNullForPartiallyValidDate() throws IOException {
        when(jsonParser.getText()).thenReturn("2025-13-01T00:00:00");

        LocalDateTime result = deserializer.deserialize(jsonParser, deserializationContext);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Integration: ObjectMapper with registered deserializer handles null-like values")
    void integration_shouldWorkWithObjectMapper() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        SimpleModule module = new SimpleModule();
        module.addDeserializer(LocalDateTime.class, new NullSafeLocalDateTimeDeserializer());
        mapper.registerModule(module);

        // Valid date
        String validJson = "{\"time\":\"2025-03-15T10:30:00\"}";
        TimeWrapper validResult = mapper.readValue(validJson, TimeWrapper.class);
        assertThat(validResult.time).isEqualTo(LocalDateTime.of(2025, 3, 15, 10, 30, 0));

        // "None" value
        String noneJson = "{\"time\":\"None\"}";
        TimeWrapper noneResult = mapper.readValue(noneJson, TimeWrapper.class);
        assertThat(noneResult.time).isNull();
    }

    // Helper class for integration test
    private static class TimeWrapper {
        public LocalDateTime time;
    }
}
