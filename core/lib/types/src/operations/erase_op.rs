use serde::{Deserialize, Serialize};

use zksync_basic_types::{AccountId, Nonce, TokenId};
use zksync_crypto::{
    params::{
        ACCOUNT_ID_BIT_WIDTH, CHUNK_BYTES, FEE_EXPONENT_BIT_WIDTH, FEE_MANTISSA_BIT_WIDTH,
        NONCE_BIT_WIDTH, TOKEN_BIT_WIDTH, TX_TYPE_BIT_WIDTH,
    },
    primitives::FromBytes,
};

use crate::{
    helpers::{pack_fee_amount, unpack_fee_amount},
    operations::error::EraseOpError,
    Erase,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseOp {
    pub tx: Erase,
}

impl EraseOp {
    pub const CHUNKS: usize = 2;
    pub const OP_CODE: u8 = 0x0c;

    pub(crate) fn get_public_data(&self) -> Vec<u8> {
        let mut data = vec![Self::OP_CODE];
        data.extend_from_slice(&self.tx.account_id.to_be_bytes());
        data.extend_from_slice(&self.tx.nonce.to_be_bytes());
        data.extend_from_slice(&self.tx.fee_token.to_be_bytes());
        data.extend_from_slice(&pack_fee_amount(&self.tx.fee));
        data.resize(Self::CHUNKS * CHUNK_BYTES, 0x00);
        data
    }

    pub fn from_public_data(bytes: &[u8]) -> Result<Self, EraseOpError> {
        if bytes.len() != Self::CHUNKS * CHUNK_BYTES {
            return Err(EraseOpError::PubdataSizeMismatch);
        }

        const FEE_BIT_WIDTH: usize = FEE_EXPONENT_BIT_WIDTH + FEE_MANTISSA_BIT_WIDTH;

        let account_offset = TX_TYPE_BIT_WIDTH / 8;
        let obsolete_offset = account_offset + ACCOUNT_ID_BIT_WIDTH / 8;
        let fee_token_offset = obsolete_offset + NONCE_BIT_WIDTH / 8;
        let fee_offset = fee_token_offset + TOKEN_BIT_WIDTH / 8;

        let account = AccountId(
            u32::from_bytes(&bytes[account_offset..obsolete_offset])
                .ok_or(EraseOpError::CannotGetAccountId)?,
        );
        let obsolete = Nonce(
            u32::from_bytes(&bytes[obsolete_offset..fee_token_offset])
                .ok_or(EraseOpError::CannotGetObsolete)?,
        );
        let fee_token = TokenId(
            u32::from_bytes(&bytes[fee_token_offset..fee_offset])
                .ok_or(EraseOpError::CannotGetTokenId)?,
        );
        let fee = unpack_fee_amount(&bytes[fee_offset..fee_offset + FEE_BIT_WIDTH / 8])
            .ok_or(EraseOpError::CannotGetFee)?;

        Ok(Self {
            tx: Erase::new(account, Default::default(), obsolete, fee, fee_token, None),
        })
    }

    pub fn get_updated_account_ids(&self) -> Vec<AccountId> {
        vec![self.tx.account_id]
    }
}
