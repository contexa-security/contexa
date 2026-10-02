package io.contexa.demo.observation.receipt.service;

import io.contexa.demo.observation.receipt.dto.ClientReceiptInput;
import io.contexa.demo.observation.receipt.dto.ClientReceiptView;

import java.util.List;
import java.util.UUID;

public interface ClientReceiptService {

    ClientReceiptView record(String arm, UUID requestId, UUID visitorId, ClientReceiptInput input);

    List<ClientReceiptView> find(String arm, UUID requestId, UUID visitorId);
}
