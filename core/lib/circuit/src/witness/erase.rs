use num::ToPrimitive;

use zksync_crypto::{
    circuit::{
        utils::{append_be_fixed_width, eth_address_to_fr, le_bit_vector_into_field_element},
        CircuitAccountTree,
    },
    franklin_crypto::{
        bellman::pairing::{
            bn256::{Bn256, Fr},
            ff::Field,
        },
        rescue::RescueEngine,
    },
    params::{
        account_tree_depth, ACCOUNT_ID_BIT_WIDTH, CHUNK_BIT_WIDTH, FEE_EXPONENT_BIT_WIDTH,
        FEE_MANTISSA_BIT_WIDTH, NONCE_BIT_WIDTH, TOKEN_BIT_WIDTH, TX_TYPE_BIT_WIDTH,
    },
    primitives::FloatConversions,
};
use zksync_types::EraseOp;

use crate::{
    operation::{Operation, OperationArguments, OperationBranch, OperationBranchWitness},
    utils::resize_grow_only,
    witness::{
        utils::{apply_leaf_operation, fr_from, get_audits},
        SigDataInput, Witness,
    },
};

#[derive(Debug)]
pub struct EraseData {
    pub account_id: u32,
    pub address: Fr,
    pub obsolete: u32,
    pub fee: u128,
    pub fee_token: u32,
}

pub struct EraseWitness<E: RescueEngine> {
    pub after_root: Option<E::Fr>,
    pub tx_type: Option<E::Fr>,
    pub args: OperationArguments<E>,

    pub account_before: OperationBranch<E>,
    pub account_after: OperationBranch<E>,
}

impl Witness for EraseWitness<Bn256> {
    type OperationType = EraseOp;
    type CalculateOpsInput = SigDataInput;

    fn apply_tx(tree: &mut CircuitAccountTree, op: &Self::OperationType) -> Self {
        let erase_data = EraseData {
            account_id: *op.tx.account_id,
            address: eth_address_to_fr(&op.tx.account),
            obsolete: *op.tx.nonce,
            fee: op.tx.fee.to_u128().unwrap(),
            fee_token: *op.tx.fee_token,
        };

        Self::apply_data(tree, &erase_data)
    }

    fn get_pubdata(&self) -> Vec<bool> {
        let mut pubdata_bits = vec![];
        append_be_fixed_width(&mut pubdata_bits, &self.tx_type.unwrap(), TX_TYPE_BIT_WIDTH);
        append_be_fixed_width(
            &mut pubdata_bits,
            &self.account_before.address.unwrap(),
            ACCOUNT_ID_BIT_WIDTH,
        );
        append_be_fixed_width(
            &mut pubdata_bits,
            &self.account_before.obsolete.unwrap(),
            NONCE_BIT_WIDTH,
        );
        append_be_fixed_width(
            &mut pubdata_bits,
            &self.account_before.token.unwrap(),
            TOKEN_BIT_WIDTH,
        );
        append_be_fixed_width(
            &mut pubdata_bits,
            &self.args.fee.unwrap(),
            FEE_MANTISSA_BIT_WIDTH + FEE_EXPONENT_BIT_WIDTH,
        );

        resize_grow_only(&mut pubdata_bits, EraseOp::CHUNKS * CHUNK_BIT_WIDTH, false);
        pubdata_bits
    }

    fn get_offset_commitment_data(&self) -> Vec<bool> {
        vec![false; EraseOp::CHUNKS * 8]
    }

    fn calculate_operations(&self, input: Self::CalculateOpsInput) -> Vec<Operation<Bn256>> {
        let pubdata_chunks: Vec<_> = self
            .get_pubdata()
            .chunks(CHUNK_BIT_WIDTH)
            .map(|x| le_bit_vector_into_field_element(&x.to_vec()))
            .collect();

        vec![
            Operation {
                new_root: self.after_root,
                tx_type: self.tx_type,
                chunk: Some(fr_from(0)),
                pubdata_chunk: Some(pubdata_chunks[0]),
                first_sig_msg: Some(input.first_sig_msg),
                second_sig_msg: Some(input.second_sig_msg),
                third_sig_msg: Some(input.third_sig_msg),
                forth_sig_msg: Some(input.forth_sig_msg),
                signature_data: input.signature.clone(),
                signer_pub_key_packed: input.signer_pub_key_packed.to_vec(),
                args: self.args.clone(),
                lhs: self.account_before.clone(),
                rhs: self.account_before.clone(),
            },
            Operation {
                new_root: self.after_root,
                tx_type: self.tx_type,
                chunk: Some(fr_from(1)),
                pubdata_chunk: Some(pubdata_chunks[1]),
                first_sig_msg: Some(input.first_sig_msg),
                second_sig_msg: Some(input.second_sig_msg),
                third_sig_msg: Some(input.third_sig_msg),
                forth_sig_msg: Some(input.forth_sig_msg),
                signature_data: input.signature.clone(),
                signer_pub_key_packed: input.signer_pub_key_packed.to_vec(),
                args: self.args.clone(),
                lhs: self.account_after.clone(),
                rhs: self.account_after.clone(),
            },
        ]
    }
}

impl EraseWitness<Bn256> {
    fn apply_data(tree: &mut CircuitAccountTree, erase: &EraseData) -> Self {
        assert_eq!(tree.capacity(), 1 << account_tree_depth());
        let account_fe = fr_from(erase.account_id);
        let obsolete_fe = fr_from(erase.obsolete);
        let fee_token_fe = fr_from(erase.fee_token);
        let fee_fe = fr_from(erase.fee);

        let fee_bits = FloatConversions::to_float(
            erase.fee,
            FEE_EXPONENT_BIT_WIDTH,
            FEE_MANTISSA_BIT_WIDTH,
            10,
        )
        .unwrap();
        let fee_encoded: Fr = le_bit_vector_into_field_element(&fee_bits);

        let init_root = tree.root_hash();
        vlog::debug!("Initial root = {}", init_root);

        let (audit_account_path, audit_balance_path, audit_signal_path) =
            get_audits(tree, erase.account_id, erase.fee_token, erase.obsolete);

        let (
            account_witness_before,
            account_witness_after,
            balance_before,
            balance_after,
            signal_before,
            signal_after,
        ) = apply_leaf_operation(
            tree,
            erase.account_id,
            erase.fee_token,
            erase.obsolete,
            |_| {},
            |bal| {
                bal.value.sub_assign(&fee_fe);
            },
            |sig| {
                sig.raise();
            },
        );

        EraseWitness {
            after_root: Some(tree.root_hash()),
            tx_type: Some(fr_from(EraseOp::OP_CODE)),
            args: OperationArguments {
                a: Some(balance_before),
                b: Some(fee_fe),
                fee: Some(fee_encoded),
                eth_address: Some(erase.address),
                ..Default::default()
            },

            account_before: OperationBranch {
                address: Some(account_fe),
                token: Some(fee_token_fe),
                obsolete: Some(obsolete_fe),
                witness: OperationBranchWitness {
                    account_witness: account_witness_before,
                    account_path: audit_account_path.clone(),
                    balance_value: Some(balance_before),
                    balance_subtree_path: audit_balance_path.clone(),
                    signal_value: Some(signal_before),
                    signal_subtree_path: audit_signal_path.clone(),
                },
            },

            account_after: OperationBranch {
                address: Some(account_fe),
                token: Some(fee_token_fe),
                obsolete: Some(obsolete_fe),
                witness: OperationBranchWitness {
                    account_witness: account_witness_after,
                    account_path: audit_account_path,
                    balance_value: Some(balance_after),
                    balance_subtree_path: audit_balance_path,
                    signal_value: Some(signal_after),
                    signal_subtree_path: audit_signal_path,
                },
            },
        }
    }
}
