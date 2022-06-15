CREATE TABLE obsoletes (
    account_id BIGINT NOT NULL REFERENCES accounts(id),
    nonce BIGINT NOT NULL,
    PRIMARY KEY (account_id, nonce)
);
