package io.contexa.demo.observation.receipt.service.impl;

import io.contexa.demo.observation.receipt.dto.ClientReceiptInput;
import io.contexa.demo.observation.receipt.dto.ClientReceiptView;
import io.contexa.demo.observation.receipt.dto.ReceiptState;
import io.contexa.demo.observation.receipt.repository.ClientReceiptRepository;
import io.contexa.demo.observation.receipt.service.ClientReceiptService;
import io.contexa.demo.observation.request.service.WorkspaceEvidenceQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultClientReceiptService implements ClientReceiptService {

    private final WorkspaceEvidenceQuery evidence;
    private final ClientReceiptRepository receipts;
    private final DocumentCodec documents;

    public DefaultClientReceiptService(WorkspaceEvidenceQuery evidence, ClientReceiptRepository receipts,
            DocumentCodec documents) {
        this.evidence = evidence;
        this.receipts = receipts;
        this.documents = documents;
    }

    @Override
    public ClientReceiptView record(String arm, UUID requestId, UUID visitorId, ClientReceiptInput input) {
        var request = evidence.find(arm, requestId, visitorId);
        if (!request.http().path().endsWith("/download")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "UNSUPPORTED_RECEIPT_TARGET");
        }
        if (input.state() == ReceiptState.COMPLETE && input.contentSha256() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "RECEIPT_HASH_REQUIRED");
        }
        Boolean matches = null;
        if (input.state() == ReceiptState.COMPLETE && request.download() != null) {
            matches = request.download().preparedBytes() == input.receivedBytes()
                    && request.download().contentSha256().equals(input.contentSha256());
        }
        ClientReceiptView receipt = new ClientReceiptView(input.id(), requestId, arm, input.state(),
                input.receivedBytes(), input.contentSha256(), input.startedAt(), input.endedAt(), Instant.now(),
                "BROWSER_REPORTED_NOT_INDEPENDENTLY_ATTESTED", matches);
        return receipts.append(visitorId, documents.hash(documents.write(input)), receipt);
    }

    @Override
    public List<ClientReceiptView> find(String arm, UUID requestId, UUID visitorId) {
        evidence.find(arm, requestId, visitorId);
        return receipts.find(arm, requestId, visitorId);
    }
}
