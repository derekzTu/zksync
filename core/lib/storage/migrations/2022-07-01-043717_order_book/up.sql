CREATE TABLE order_book (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts(id),
    recipient_address BYTEA NOT NULL,
    nonce BIGINT NOT NULL,
    token_buy BIGINT NOT NULL REFERENCES tokens(id),
    token_sell BIGINT NOT NULL REFERENCES tokens(id),
    sell_price NUMERIC NOT NULL,
    buy_price NUMERIC NOT NULL,
    earnest_price NUMERIC NOT NULL,
    amount NUMERIC NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_thru TIMESTAMP WITH TIME ZONE NOT NULL,
    signature JSONB NOT NULL,
    eth_signature JSONB,
    UNIQUE (account_id, nonce)
);
