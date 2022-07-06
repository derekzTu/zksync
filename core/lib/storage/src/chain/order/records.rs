use chrono::{DateTime, Utc};
use num::bigint::ToBigInt;
use sqlx::{types::BigDecimal, FromRow};
use zksync_api_types::OrderWithSignature;

use zksync_types::{tx::TimeRange, AccountId, Address, Nonce, Order, TokenId};

#[derive(Debug, FromRow, Clone)]
pub struct StorageOrder {
    pub id: i64,
    pub account_id: i64,
    pub recipient_address: Vec<u8>,
    pub nonce: i64,
    pub token_buy: i64,
    pub token_sell: i64,
    // price
    pub sell_price: BigDecimal,
    pub buy_price: BigDecimal,
    pub earnest_price: BigDecimal,
    pub amount: BigDecimal,
    // time_range
    pub valid_from: DateTime<Utc>,
    pub valid_thru: DateTime<Utc>,
    pub signature: serde_json::Value,
    pub eth_signature: Option<serde_json::Value>,
}

impl From<StorageOrder> for OrderWithSignature {
    fn from(val: StorageOrder) -> Self {
        let to_biguint = |decimal: BigDecimal| decimal.to_bigint().unwrap().to_biguint().unwrap();

        OrderWithSignature {
            order: Order {
                account_id: AccountId(val.account_id as u32),
                recipient_address: Address::from_slice(&val.recipient_address),
                nonce: Nonce(val.nonce as u32),
                token_buy: TokenId(val.token_buy as u32),
                token_sell: TokenId(val.token_sell as u32),
                price: (
                    to_biguint(val.sell_price),
                    to_biguint(val.buy_price),
                    to_biguint(val.earnest_price),
                ),
                amount: to_biguint(val.amount),
                time_range: TimeRange::new(
                    val.valid_from.timestamp() as u64,
                    val.valid_thru.timestamp() as u64,
                ),
                signature: serde_json::from_value(val.signature).unwrap(),
            },
            signature: val
                .eth_signature
                .map(|v| serde_json::from_value(v).unwrap()),
        }
    }
}
