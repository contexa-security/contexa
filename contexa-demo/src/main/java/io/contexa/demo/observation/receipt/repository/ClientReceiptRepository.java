package io.contexa.demo.observation.receipt.repository;

import io.contexa.demo.observation.receipt.dto.ClientReceiptView;

import java.util.List;
import java.util.UUID;

public interface ClientReceiptRepository {

    ClientReceiptView append(UUID visitorId, String inputSha256, ClientReceiptView receipt);

    List<ClientReceiptView> find(String arm, UUID requestId, UUID visitorId);
}
