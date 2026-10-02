package io.contexa.demo.shared.document;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

@Component
@Primary
public class JacksonDocumentCodec extends AbstractJacksonDocumentCodec {

    public JacksonDocumentCodec(ObjectMapper mapper) {
        super(mapper);
    }
}
