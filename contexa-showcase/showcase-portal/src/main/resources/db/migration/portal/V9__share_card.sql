-- Share cards (deck p.15, docs/showcase/P5-설계.md section 4): the result values only. Visitors with the same result
-- share one card, so no visitor identifier is stored and the number of cards is bounded by the result combinations.
-- A visitor who did not vote has my_total 0. Cards are deleted 90 days after they were last shared.
CREATE TABLE share_card (
    share_key       VARCHAR(16)  PRIMARY KEY,
    pair_key        VARCHAR(16)  NOT NULL,
    language        VARCHAR(2)   NOT NULL,
    my_hits         INTEGER      NOT NULL CHECK (my_hits >= 0),
    my_total        INTEGER      NOT NULL CHECK (my_total >= 0),
    contexa_hits    INTEGER      NOT NULL CHECK (contexa_hits >= 0),
    contexa_total   INTEGER      NOT NULL CHECK (contexa_total > 0),
    host            VARCHAR(253) NOT NULL,
    image           BYTEA        NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_shared_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT share_card_language_chk CHECK (language IN ('ko', 'en')),
    CONSTRAINT share_card_scores_chk CHECK (my_hits <= my_total AND contexa_hits <= contexa_total),
    CONSTRAINT share_card_result_uq UNIQUE (pair_key, language, my_hits, my_total, contexa_hits, contexa_total, host)
);

CREATE INDEX share_card_last_shared_idx ON share_card (last_shared_at);
