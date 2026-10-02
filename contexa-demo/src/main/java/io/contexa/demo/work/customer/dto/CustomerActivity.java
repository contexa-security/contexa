package io.contexa.demo.work.customer.dto;

import io.contexa.demo.work.shared.dto.WorkText;

import java.time.Instant;

public record CustomerActivity(
        Instant occurredAt,
        WorkText title,
        WorkText note) {
}
