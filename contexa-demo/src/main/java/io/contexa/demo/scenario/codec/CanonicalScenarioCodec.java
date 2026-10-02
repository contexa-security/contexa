package io.contexa.demo.scenario.codec;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.contexa.demo.shared.document.AbstractJacksonDocumentCodec;
import org.springframework.stereotype.Component;

@Component
public class CanonicalScenarioCodec extends AbstractJacksonDocumentCodec implements ScenarioCodec {

    public CanonicalScenarioCodec(ObjectMapper mapper) {
        super(mapper.copy().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
                .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true));
    }
}
