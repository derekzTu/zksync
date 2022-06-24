use num::BigUint;
use zksync_crypto::franklin_crypto::bellman::pairing::bn256::Bn256;
use zksync_state::{handler::TxHandler, state::ZkSyncState};
use zksync_types::{AccountId, Erase, EraseOp, Nonce, Obsolete, TokenId};

use crate::witness::{
    erase::EraseWitness,
    tests::test_utils::{generic_test_scenario, WitnessTestAccount},
    SigDataInput,
};

struct TestErase {
    account: u32,
    obsoletes: Vec<u32>,
    fee_token: u32,
    balance: u64,
    fee: u64,
    nonce: u32,
    test_account: Option<WitnessTestAccount>,
}

type EraseSigDataInput = SigDataInput;

impl TestErase {
    fn create_account(&mut self) {
        if self.test_account.is_some() {
            return;
        }

        let mut acc = WitnessTestAccount::new_with_token(
            AccountId(self.account),
            TokenId(self.fee_token),
            self.balance,
        );
        self.obsoletes.iter().for_each(|n| {
            acc.account.apply_obsolete(Obsolete::new(Nonce(*n)));
        });

        self.test_account = Some(acc);
    }

    fn get_accounts(&self) -> Vec<WitnessTestAccount> {
        self.test_account.clone().into_iter().collect()
    }

    fn get_op(&self) -> (EraseOp, EraseSigDataInput) {
        let erase_op = EraseOp {
            tx: self
                .test_account
                .clone()
                .unwrap()
                .zksync_account
                .sign_erase(
                    Nonce(self.nonce),
                    TokenId(self.fee_token),
                    "",
                    BigUint::from(self.fee),
                )
                .0,
        };
        let input = SigDataInput::from_erase_op(&erase_op).expect("SigDataInput creation failed");

        (erase_op, input)
    }
}

#[test]
#[ignore]
fn test_erase_success() {
    let mut test_erases = vec![TestErase {
        account: 1,
        obsoletes: vec![],
        fee_token: 0,
        balance: 100,
        fee: 25,
        nonce: 0,
        test_account: None,
    }];

    for test_erase in test_erases.iter_mut() {
        test_erase.create_account();
        let (erase_op, input) = test_erase.get_op();

        generic_test_scenario::<EraseWitness<Bn256>, _>(
            &test_erase.get_accounts(),
            erase_op,
            input,
            |state, op| {
                let fee = <ZkSyncState as TxHandler<Erase>>::apply_op(state, &op)
                    .expect("Operation failed")
                    .0
                    .unwrap();
                vec![fee]
            },
        );
    }
}
