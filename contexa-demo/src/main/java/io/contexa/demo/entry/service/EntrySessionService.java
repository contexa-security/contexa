package io.contexa.demo.entry.service;

import io.contexa.demo.entry.dto.EntryLocation;
import io.contexa.demo.entry.dto.EntrySession;

public interface EntrySessionService {

    EntrySession inspect(String tokenHash);

    EntryLocation location();
}
