use chrono::{offset::TimeZone, Utc};
use num::BigInt;
use sqlx::types::BigDecimal;
use zksync_api_types::OrderWithSignature;
use zksync_types::{tx::TxEthSignature, Order};

use self::records::*;
use crate::{QueryResult, StorageProcessor};

pub mod records;

#[derive(Debug)]
pub struct OrderSchema<'a, 'c>(pub &'a mut StorageProcessor<'c>);

impl<'a, 'c> OrderSchema<'a, 'c> {
    pub async fn store_order(
        &mut self,
        OrderWithSignature { order, signature }: &OrderWithSignature,
    ) -> QueryResult<u64> {
        let mut transaction = self.0.start_transaction().await?;
        let id = sqlx::query!(
            "INSERT INTO order_book (
                account_id, recipient_address, nonce,
                token_buy, token_sell,
                sell_price, buy_price, earnest_price,
                amount,
                valid_from, valid_thru,
                signature, eth_signature
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
            ) RETURNING id",
            i64::from(*order.account_id),
            order.recipient_address.as_bytes(),
            i64::from(*order.nonce),
            i64::from(*order.token_buy),
            i64::from(*order.token_sell),
            BigDecimal::from(BigInt::from(order.price.0.clone())),
            BigDecimal::from(BigInt::from(order.price.1.clone())),
            BigDecimal::from(BigInt::from(order.price.2.clone())),
            BigDecimal::from(BigInt::from(order.amount.clone())),
            Utc.timestamp(order.time_range.valid_from as i64, 0),
            Utc.timestamp(order.time_range.valid_until as i64, 0),
            serde_json::to_value(order.signature.clone()).expect("signature serialize fail"),
            signature
                .clone()
                .map(|s| serde_json::to_value(s).expect("eth_signature serialize fail")),
        )
        .fetch_one(transaction.conn())
        .await?
        .id;

        transaction.commit().await?;

        Ok(id as u64)
    }

    pub async fn order_by_id(&mut self, id: u64) -> QueryResult<OrderWithSignature> {
        let order = sqlx::query_as!(
            StorageOrder,
            "SELECT * FROM order_book WHERE id = $1",
            id as i64,
        )
        .fetch_one(self.0.conn())
        .await?;

        Ok(order.into())
    }
}
