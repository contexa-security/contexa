package io.contexa.demo.work.export.service;

import io.contexa.demo.work.export.dto.ExportInput;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.work.participant.dto.WorkParticipant;

import java.util.UUID;

public interface ExportRequestPreparation {

    ExportRequestSnapshot prepare(UUID requestId, WorkParticipant participant, ExportInput input);
}
