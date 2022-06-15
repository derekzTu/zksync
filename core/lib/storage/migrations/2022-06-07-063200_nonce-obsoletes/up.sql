ALTER TABLE account_balance_updates ADD COLUMN obsolete BIGINT;
ALTER TABLE account_balance_updates ADD COLUMN reset bool;
UPDATE account_balance_updates SET reset = false;
ALTER TABLE account_balance_updates ALTER COLUMN reset SET NOT NULL;
