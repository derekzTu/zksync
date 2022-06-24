use std::time::Instant;
use zksync_crypto::params::max_processable_token;
use zksync_types::{operations::EraseOp, AccountUpdates, Erase, Obsolete, PubKeyHash, ZkSyncOp};

use crate::{
    handler::{error::EraseOpError, TxHandler},
    state::{BalanceUpdate::*, CollectedFee, OpSuccess, ZkSyncState},
};

impl TxHandler<Erase> for ZkSyncState {
    type Op = EraseOp;
    type OpError = EraseOpError;

    fn create_op(&self, tx: Erase) -> Result<Self::Op, Self::OpError> {
        invariant!(
            tx.fee_token <= max_processable_token(),
            EraseOpError::InvalidTokenId
        );
        let account = self
            .get_account(tx.account_id)
            .ok_or(EraseOpError::AccountNotFound)?;
        invariant!(
            account.pub_key_hash != PubKeyHash::default(),
            EraseOpError::AccountIsLocked
        );

        if let Some((pub_key_hash, _)) = tx.verify_signature() {
            if pub_key_hash != account.pub_key_hash {
                return Err(EraseOpError::InvalidSignature);
            }
        }

        let op = EraseOp { tx };

        Ok(op)
    }

    fn apply_tx(&mut self, tx: Erase) -> Result<OpSuccess, Self::OpError> {
        let op = self.create_op(tx)?;

        let (fee, updates) = <Self as TxHandler<Erase>>::apply_op(self, &op)?;
        let result = OpSuccess {
            fee,
            updates,
            executed_op: ZkSyncOp::Erase(Box::new(op)),
        };

        Ok(result)
    }

    fn apply_op(
        &mut self,
        op: &Self::Op,
    ) -> Result<(Option<CollectedFee>, AccountUpdates), Self::OpError> {
        self.apply_erase_op(op)
    }
}

impl ZkSyncState {
    fn apply_erase_op(
        &mut self,
        op: &EraseOp,
    ) -> Result<(Option<CollectedFee>, AccountUpdates), EraseOpError> {
        let start = Instant::now();

        let account = self
            .get_account(op.tx.account_id)
            .ok_or(EraseOpError::NonceObsolete)?;
        let old_balance = account.get_balance(op.tx.fee_token);
        invariant!(
            !account.obsoletes.contains(&op.tx.nonce),
            EraseOpError::NonceObsolete
        );
        invariant!(old_balance >= op.tx.fee, EraseOpError::InsufficientBalance);

        let updates = vec![self.update_account(
            op.tx.account_id,
            op.tx.fee_token,
            Sub(op.tx.fee.clone()),
            Some(Obsolete::new(op.tx.nonce)),
        )];
        let fee = CollectedFee {
            token: op.tx.fee_token,
            amount: op.tx.fee.clone(),
        };

        metrics::histogram!("state.erase", start.elapsed());
        Ok((Some(fee), updates))
    }
}
