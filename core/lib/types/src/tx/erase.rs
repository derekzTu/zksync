use num::BigUint;
use serde::{Deserialize, Serialize};

use zksync_basic_types::{AccountId, Address, Nonce, TokenId};
use zksync_crypto::{
    franklin_crypto::eddsa::PrivateKey,
    params::{max_account_id, max_processable_token, CURRENT_TX_VERSION},
    Engine,
};
use zksync_utils::{format_units, BigUintSerdeAsRadix10Str};

use crate::{
    helpers::pack_fee_amount,
    tx::{error::TransactionSignatureError, TxSignature, TxVersion, VerifiedSignatureCache},
    PubKeyHash,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Erase {
    pub account_id: AccountId,
    pub account: Address,
    pub nonce: Nonce,
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub fee: BigUint,
    pub fee_token: TokenId,
    pub signature: TxSignature,
    #[serde(skip)]
    cached_signer: VerifiedSignatureCache,
}

impl Erase {
    pub const TX_TYPE: u8 = 12;

    pub fn new(
        account_id: AccountId,
        account: Address,
        nonce: Nonce,
        fee: BigUint,
        fee_token: TokenId,
        signature: Option<TxSignature>,
    ) -> Self {
        let mut tx = Self {
            account_id,
            account,
            nonce,
            fee,
            fee_token,
            signature: signature.clone().unwrap_or_default(),
            cached_signer: VerifiedSignatureCache::NotCached,
        };
        if signature.is_some() {
            tx.cached_signer = VerifiedSignatureCache::Cached(tx.verify_signature());
        }
        tx
    }

    pub fn new_signed(
        account_id: AccountId,
        account: Address,
        nonce: Nonce,
        fee: BigUint,
        fee_token: TokenId,
        private_key: &PrivateKey<Engine>,
    ) -> Result<Self, TransactionSignatureError> {
        let mut tx = Self::new(account_id, account, nonce, fee, fee_token, None);
        tx.signature = TxSignature::sign_musig(private_key, &tx.get_bytes());
        if !tx.check_correctness() {
            return Err(TransactionSignatureError);
        }
        Ok(tx)
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        self.get_bytes_with_version(CURRENT_TX_VERSION)
    }

    pub fn get_bytes_with_version(&self, version: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[255u8 - Self::TX_TYPE]);
        out.extend_from_slice(&[version]);
        out.extend_from_slice(&self.account_id.to_be_bytes());
        out.extend_from_slice(&self.account.as_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.fee_token.to_be_bytes());
        out.extend_from_slice(&pack_fee_amount(&self.fee));
        out
    }

    pub fn check_correctness(&mut self) -> bool {
        if self.account_id <= max_account_id() && self.fee_token <= max_processable_token() {
            let signer = self.verify_signature();
            self.cached_signer = VerifiedSignatureCache::Cached(signer);
            return signer.is_some();
        }

        false
    }

    pub fn verify_signature(&self) -> Option<(PubKeyHash, TxVersion)> {
        if let VerifiedSignatureCache::Cached(cached_signer) = &self.cached_signer {
            *cached_signer
        } else {
            self.signature
                .verify_musig(&self.get_bytes())
                .map(|pub_key| (PubKeyHash::from_pubkey(&pub_key), TxVersion::V1))
        }
    }

    pub fn get_ethereum_sign_message_part(&self, token_symbol: &str, decimals: u8) -> String {
        format!(
            "Fee: {fee} {token}",
            fee = format_units(self.fee.clone(), decimals),
            token = token_symbol
        )
    }

    pub fn get_ethereum_sign_message(&self, token_symbol: &str, decimals: u8) -> String {
        let mut message = self.get_ethereum_sign_message_part(token_symbol, decimals);
        if !message.is_empty() {
            message.push('\n');
        }
        message.push_str(format!("Nonce: {}", self.nonce).as_str());
        message
    }
}
