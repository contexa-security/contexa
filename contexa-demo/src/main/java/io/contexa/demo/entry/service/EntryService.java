package io.contexa.demo.entry.service;

import io.contexa.demo.entry.dto.EntryResult;

import java.util.UUID;

public interface EntryService {

    EntryResult request(String tokenHash, UUID requestId, String email, String ip, String language);

    EntryResult verify(String tokenHash, UUID requestId, String code, String newHash);
}
