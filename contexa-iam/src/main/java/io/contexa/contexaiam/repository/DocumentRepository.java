package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.Document;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DocumentRepository extends JpaRepository<Document, Long> { }