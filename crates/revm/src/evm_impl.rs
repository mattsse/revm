use crate::{
    db::Database,
    error::{ExitError, ExitReason, ExitSucceed},
    instructions::gas,
    machine,
    machine::{Contract, Gas, Machine},
    models::SelfDestructResult,
    spec::{Spec, SpecId::*},
    subroutine::{Account, State, SubRoutine},
    util, CallContext, CreateScheme, Env, ExitRevert, Inspector, Log, TransactOut, TransactTo,
    Transfer, KECCAK_EMPTY,
};
use alloc::vec::Vec;
use bytes::Bytes;
use core::{cmp::min, marker::PhantomData};
use hashbrown::HashMap as Map;
use primitive_types::{H160, H256, U256};
use revm_precompiles::{Precompile, PrecompileOutput, Precompiles};
use sha3::{Digest, Keccak256};

pub struct EVMImpl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> {
    db: &'a mut DB,
    env: &'a Env,
    subroutine: SubRoutine,
    precompiles: Precompiles,
    inspector: &'a mut dyn Inspector,
    _phantomdata: PhantomData<GSPEC>,
}

pub trait Transact {
    /// Do transaction.
    /// Return ExitReason, Output for call or Address if we are creating contract, gas spend, State that needs to be applied.
    fn transact(&mut self) -> (ExitReason, TransactOut, u64, State);
}

impl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> Transact
    for EVMImpl<'a, GSPEC, DB, INSPECT>
{
    fn transact(&mut self) -> (ExitReason, TransactOut, u64, State) {
        let caller = self.env.tx.caller;
        let value = self.env.tx.value;
        let data = self.env.tx.data.clone();
        let gas_limit = self.env.tx.gas_limit;
        let exit_error = |reason: ExitReason| (reason, TransactOut::None, 0, State::new());

        if GSPEC::enabled(LONDON) {
            if let Some(priority_fee) = self.env.tx.gas_priority_fee {
                if priority_fee > self.env.tx.gas_price {
                    // or gas_max_fee for eip1559
                    return exit_error(ExitError::GasMaxFeeGreaterThanPriorityFee.into());
                }
            }
            let effective_gas_price = self.env.effective_gas_price();
            let basefee = self.env.block.basefee;

            // check minimal cost against basefee
            // TODO maybe do this checks when creating evm. We already have all data there
            // or should be move effective_gas_price inside transact fn
            if effective_gas_price < basefee {
                return exit_error(ExitError::GasPriceLessThenBasefee.into());
            }
            // check if priority fee is lower then max fee
        }
        // unusual to be found here, but check if gas_limit is more then block_gas_limit
        if U256::from(gas_limit) > self.env.block.gas_limit {
            return exit_error(ExitError::CallerGasLimitMoreThenBlock.into());
        }

        let mut gas = Gas::new(gas_limit);
        // record initial gas cost. if not using gas metering init will return 0
        if !gas.record_cost(self.initialization::<GSPEC>()) {
            return exit_error(ExitError::OutOfGas.into());
        }

        // load acc
        self.inner_load_account(caller);

        // EIP-3607: Reject transactions from senders with deployed code
        // This EIP is introduced after london but there was no colision in past
        // so we can leave it enabled always
        if self.subroutine.account(caller).info.code_hash != KECCAK_EMPTY {
            return exit_error(ExitError::RejectCallerWithCode.into());
        }

        // substract gas_limit*gas_price from current account.
        if let Some(payment_value) =
            U256::from(gas_limit).checked_mul(self.env.effective_gas_price())
        {
            if !self.subroutine.balance_sub(caller, payment_value) {
                return exit_error(ExitError::LackOfFundForGasLimit.into());
            }
        } else {
            return exit_error(ExitError::OverflowPayment.into());
        }

        // check if we have enought balance for value transfer.
        let difference = self.env.tx.gas_price - self.env.effective_gas_price();
        if difference + value > self.subroutine.account(caller).info.balance {
            return exit_error(ExitError::OutOfFund.into());
        }

        // record all as cost;
        let gas_limit = gas.remaining();
        if crate::USE_GAS {
            gas.record_cost(gas_limit);
        }
        
        let timer = std::time::Instant::now();

        // call inner handling of call/create
        let (exit_reason, ret_gas, out) = match self.env.tx.transact_to {
            TransactTo::Call(address) => {
                self.subroutine.inc_nonce(caller);
                let context = CallContext {
                    caller,
                    address,
                    apparent_value: value,
                };
                let (exit, gas, bytes) = self.call_inner::<GSPEC>(
                    address,
                    Transfer {
                        source: caller,
                        target: address,
                        value,
                    },
                    data,
                    gas_limit,
                    context,
                );
                (exit, gas, TransactOut::Call(bytes))
            }
            TransactTo::Create(scheme) => {
                let (exit, address, ret_gas, bytes) =
                    self.create_inner::<GSPEC>(caller, scheme, value, data, gas_limit);
                (exit, ret_gas, TransactOut::Create(bytes, address))
            }
        };
        let elapsed = timer.elapsed();
        println!("Elapsed inside:{:?}",elapsed);
        if crate::USE_GAS {
            gas.reimburse_unspend(&exit_reason, ret_gas);
        }
        match self.finalize::<GSPEC>(caller, &gas) {
            Err(e) => (e, out, gas.spend(), Map::new()),
            Ok(state) => (exit_reason, out, gas.spend(), state),
        }
    }
}

impl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> EVMImpl<'a, GSPEC, DB, INSPECT> {
    pub fn new(
        db: &'a mut DB,
        env: &'a Env,
        inspector: &'a mut dyn Inspector,
        precompiles: Precompiles,
    ) -> Self {
        let mut precompile_acc = Map::new();
        for (add, _) in precompiles.as_slice() {
            precompile_acc.insert(add.clone(), db.basic(add.clone()));
        }
        Self {
            db,
            env,
            subroutine: SubRoutine::new(precompile_acc),
            precompiles,
            inspector,
            _phantomdata: PhantomData {},
        }
    }

    fn finalize<SPEC: Spec>(
        &mut self,
        caller: H160,
        gas: &Gas,
    ) -> Result<Map<H160, Account>, ExitReason> {
        let coinbase = self.env.block.coinbase;
        if crate::USE_GAS {
            let effective_gas_price = self.env.effective_gas_price();
            let basefee = self.env.block.basefee;
            let max_refund_quotient = if SPEC::enabled(LONDON) { 5 } else { 2 }; // EIP-3529: Reduction in refunds
            let gas_refunded = min(gas.refunded() as u64, gas.spend() / max_refund_quotient);
            self.subroutine.balance_add(
                caller,
                effective_gas_price * (gas.remaining() + gas_refunded),
            );
            let coinbase_gas_price = if SPEC::enabled(LONDON) {
                effective_gas_price.saturating_sub(basefee)
            } else {
                effective_gas_price
            };

            self.subroutine.load_account(coinbase, self.db);
            self.subroutine
                .balance_add(coinbase, coinbase_gas_price * (gas.spend() - gas_refunded));
        } else {
            // touch coinbase
            self.subroutine.load_account(coinbase, self.db);
            self.subroutine.balance_add(coinbase, U256::zero());
        }
        Ok(self.subroutine.finalize())
    }

    fn inner_load_account(&mut self, caller: H160) -> bool {
        let is_cold = self.subroutine.load_account(caller, self.db);
        if INSPECT && is_cold {
            self.inspector.load_account(&caller);
        }
        is_cold
    }

    fn initialization<SPEC: Spec>(&mut self) -> u64 {
        let is_create = matches!(self.env.tx.transact_to, TransactTo::Create(_));
        let input = &self.env.tx.data;
        let access_list = self.env.tx.access_list.clone();
        for (ward_acc, _) in self.precompiles.as_slice() {
            //TODO trace load precompiles?
            self.subroutine.load_account(ward_acc.clone(), self.db);
        }

        if crate::USE_GAS {
            let zero_data_len = input.iter().filter(|v| **v == 0).count() as u64;
            let non_zero_data_len = (input.len() as u64 - zero_data_len) as u64;
            let (accessed_accounts, accessed_slots) = {
                if SPEC::enabled(BERLIN) {
                    let mut accessed_slots = 0 as u64;
                    let accessed_accounts = access_list.len() as u64;

                    for (address, slots) in access_list {
                        //TODO trace load access_list?
                        self.subroutine.load_account(address, self.db);
                        accessed_slots += slots.len() as u64;
                        for slot in slots {
                            self.subroutine.sload(address, slot, self.db);
                        }
                    }
                    (accessed_accounts, accessed_slots)
                } else {
                    (0, 0)
                }
            };

            let transact = if is_create {
                if SPEC::enabled(HOMESTEAD) {
                    // EIP-2: Homestead Hard-fork Changes
                    53000
                } else {
                    21000
                }
            } else {
                21000
            };

            // EIP-2028: Transaction data gas cost reduction
            let gas_transaction_non_zero_data = if SPEC::enabled(ISTANBUL) { 16 } else { 68 };

            transact
                + zero_data_len * gas::TRANSACTION_ZERO_DATA
                + non_zero_data_len * gas_transaction_non_zero_data
                + accessed_accounts * gas::ACCESS_LIST_ADDRESS
                + accessed_slots * gas::ACCESS_LIST_STORAGE_KEY
        } else {
            0
        }
    }

    fn create_inner<SPEC: Spec>(
        &mut self,
        caller: H160,
        scheme: CreateScheme,
        value: U256,
        init_code: Bytes,
        gas_limit: u64,
    ) -> (ExitReason, Option<H160>, Gas, Bytes) {
        let gas = Gas::new(gas_limit);
        self.load_account(caller);

        // check depth of calls
        if self.subroutine.depth() > machine::CALL_STACK_LIMIT {
            return (ExitRevert::CallTooDeep.into(), None, gas, Bytes::new());
        }
        // check balance of caller and value. Do this before increasing nonce
        if self.balance(caller).0 < value {
            return (ExitRevert::OutOfFund.into(), None, gas, Bytes::new());
        }

        // inc nonce of caller
        let old_nonce = self.subroutine.inc_nonce(caller);
        // create address
        let code_hash = H256::from_slice(Keccak256::digest(&init_code).as_slice());
        let created_address = match scheme {
            CreateScheme::Create => util::create_address(caller, old_nonce),
            CreateScheme::Create2 { salt } => util::create2_address(caller, code_hash, salt),
        };
        let ret = Some(created_address);

        // load account so that it will be hot
        self.load_account(created_address);

        // enter into subroutine
        let checkpoint = self.subroutine.create_checkpoint();

        // create contract account and check for collision
        if !self.subroutine.new_contract_acc(
            created_address,
            self.precompiles.contains(&created_address),
            self.db,
        ) {
            self.subroutine.checkpoint_revert(checkpoint);
            return (ExitError::CreateCollision.into(), ret, gas, Bytes::new());
        }

        // transfer value to contract address
        if let Err(e) = self
            .subroutine
            .transfer(caller, created_address, value, self.db)
        {
            self.subroutine.checkpoint_revert(checkpoint);
            return (e.into(), ret, gas, Bytes::new());
        }
        // inc nonce of contract
        if SPEC::enabled(ISTANBUL) {
            self.subroutine.inc_nonce(created_address);
        }
        // create new machine and execute init function
        let contract = Contract::new(Bytes::new(), init_code, created_address, caller, value);
        let mut machine = Machine::new::<SPEC>(contract, gas.limit(), self.subroutine.depth());
        let exit_reason = machine.run::<Self, SPEC>(self);
        // handler error if present on execution\
        match exit_reason {
            ExitReason::Succeed(_) => {
                let b = Bytes::new();
                // if ok, check contract creation limit and calculate gas deduction on output len.
                let code = machine.return_value();

                // EIP-3541: Reject new contract code starting with the 0xEF byte
                if SPEC::enabled(LONDON) && !code.is_empty() && code.get(0) == Some(&0xEF) {
                    self.subroutine.checkpoint_revert(checkpoint);
                    return (ExitError::CreateContractWithEF.into(), ret, machine.gas, b);
                }

                // EIP-170: Contract code size limit
                if SPEC::enabled(SPURIOUS_DRAGON) && code.len() > 0x6000 {
                    self.subroutine.checkpoint_revert(checkpoint);
                    return (ExitError::CreateContractLimit.into(), ret, machine.gas, b);
                }
                if crate::USE_GAS {
                    let gas_for_code = code.len() as u64 * crate::instructions::gas::CODEDEPOSIT;
                    // record code deposit gas cost and check if we are out of gas.
                    if !machine.gas.record_cost(gas_for_code) {
                        self.subroutine.checkpoint_revert(checkpoint);
                        return (ExitError::OutOfGas.into(), ret, machine.gas, b);
                    }
                }
                // if we have enought gas
                self.subroutine.checkpoint_commit();
                let code_hash = H256::from_slice(Keccak256::digest(&code).as_slice());
                self.subroutine.set_code(created_address, code, code_hash);
                (ExitSucceed::Returned.into(), ret, machine.gas, b)
            }
            _ => {
                self.subroutine.checkpoint_revert(checkpoint);
                (exit_reason, ret, machine.gas, machine.return_value())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn call_inner<SPEC: Spec>(
        &mut self,
        code_address: H160,
        transfer: Transfer,
        input: Bytes,
        gas_limit: u64,
        context: CallContext,
    ) -> (ExitReason, Gas, Bytes) {
        let mut gas = Gas::new(gas_limit);
        // Load account and get code. Account is now hot.
        let (code, _) = self.code(code_address);

        // check depth
        if self.subroutine.depth() > machine::CALL_STACK_LIMIT {
            return (ExitRevert::CallTooDeep.into(), gas, Bytes::new());
        }

        // Create subroutine checkpoint
        let checkpoint = self.subroutine.create_checkpoint();
        // touch address. For "EIP-158 State Clear" this will erase empty accounts.
        if transfer.value == U256::zero() {
            self.load_account(context.address);
            self.subroutine.balance_add(context.address, U256::zero()); // touch the acc
        }

        // transfer value from caller to called account;
        match self
            .subroutine
            .transfer(transfer.source, transfer.target, transfer.value, self.db)
        {
            Err(e) => {
                self.subroutine.checkpoint_revert(checkpoint);
                return (e.into(), gas, Bytes::new());
            }
            Ok((source_is_cold, target_is_cold)) => {
                if INSPECT && source_is_cold {
                    self.inspector.load_account(&transfer.source);
                }
                if INSPECT && target_is_cold {
                    self.inspector.load_account(&transfer.target);
                }
            }
        }

        // call precompiles
        if let Some(precompile) = self.precompiles.get(&code_address) {
            let out = match precompile {
                Precompile::Standard(fun) => fun(input.as_ref(), gas_limit),
                Precompile::Custom(fun) => fun(input.as_ref(), gas_limit),
            };
            match out {
                Ok(PrecompileOutput { output, cost, logs }) => {
                    if !crate::USE_GAS || gas.record_cost(cost) {
                        logs.into_iter().for_each(|l| {
                            self.subroutine.log(Log {
                                address: l.address,
                                topics: l.topics,
                                data: l.data,
                            })
                        });
                        self.subroutine.checkpoint_commit();
                        (ExitSucceed::Returned.into(), gas, Bytes::from(output))
                    } else {
                        self.subroutine.checkpoint_revert(checkpoint);
                        (ExitError::OutOfGas.into(), gas, Bytes::new())
                    }
                }
                Err(e) => {
                    self.subroutine.checkpoint_revert(checkpoint); //TODO check if we are discarding or reverting
                    (ExitError::Precompile(e).into(), gas, Bytes::new())
                }
            }
        } else {
            // create machine and execute subcall
            let contract = Contract::new_with_context(input, code, &context);
            let mut machine = Machine::new::<SPEC>(contract, gas_limit, self.subroutine.depth());
            let exit_reason = machine.run::<Self, SPEC>(self);
            if matches!(exit_reason, ExitReason::Succeed(_)) {
                self.subroutine.checkpoint_commit();
            } else {
                self.subroutine.checkpoint_revert(checkpoint);
            }

            (exit_reason, machine.gas, machine.return_value())
        }
    }
}

impl<'a, GSPEC: Spec, DB: Database, const INSPECT: bool> Handler
    for EVMImpl<'a, GSPEC, DB, INSPECT>
{
    const INSPECT: bool = INSPECT;

    fn env(&self) -> &Env {
        &self.env
    }

    fn inspect(&mut self) -> &mut dyn Inspector {
        self.inspector
    }

    fn block_hash(&mut self, number: U256) -> H256 {
        self.db.block_hash(number)
    }

    fn load_account(&mut self, address: H160) -> (bool, bool) {
        let (is_cold, exists) = self.subroutine.load_account_exist(address, self.db);
        if INSPECT && is_cold {
            self.inspector.load_account(&address);
        }
        (is_cold, exists)
    }

    fn balance(&mut self, address: H160) -> (U256, bool) {
        let is_cold = self.inner_load_account(address);
        let balance = self.subroutine.account(address).info.balance;
        (balance, is_cold)
    }

    fn code(&mut self, address: H160) -> (Bytes, bool) {
        let (acc, is_cold) = self.subroutine.load_code(address, self.db);
        if INSPECT && is_cold {
            self.inspector.load_account(&address);
        }
        (acc.info.code.clone().unwrap(), is_cold)
    }

    /// Get code hash of address.
    fn code_hash(&mut self, address: H160) -> (H256, bool) {
        let (acc, is_cold) = self.subroutine.load_code(address, self.db);
        if INSPECT && is_cold {
            self.inspector.load_account(&address);
        }
        if acc.is_empty() {
            return (H256::zero(), is_cold);
        }

        (
            H256::from_slice(Keccak256::digest(&acc.info.code.clone().unwrap()).as_slice()),
            is_cold,
        )
    }

    fn sload(&mut self, address: H160, index: H256) -> (H256, bool) {
        // account is allways hot. reference on that statement https://eips.ethereum.org/EIPS/eip-2929 see `Note 2:`
        self.subroutine.sload(address, index, self.db)
    }

    fn sstore(&mut self, address: H160, index: H256, value: H256) -> (H256, H256, H256, bool) {
        self.subroutine.sstore(address, index, value, self.db)
    }

    fn log(&mut self, address: H160, topics: Vec<H256>, data: Bytes) {
        let log = Log {
            address,
            topics,
            data,
        };
        self.subroutine.log(log);
    }

    fn selfdestruct(&mut self, address: H160, target: H160) -> SelfDestructResult {
        let res = self.subroutine.selfdestruct(address, target, self.db);
        if INSPECT && res.is_cold {
            self.inspector.load_account(&target);
        }
        res
    }

    fn create<SPEC: Spec>(
        &mut self,
        caller: H160,
        scheme: CreateScheme,
        value: U256,
        init_code: Bytes,
        gas: u64,
    ) -> (ExitReason, Option<H160>, Gas, Bytes) {
        self.create_inner::<SPEC>(caller, scheme, value, init_code, gas)
    }

    fn call<SPEC: Spec>(
        &mut self,
        code_address: H160,
        transfer: Transfer,
        input: Bytes,
        gas: u64,
        context: CallContext,
    ) -> (ExitReason, Gas, Bytes) {
        self.call_inner::<SPEC>(code_address, transfer, input, gas, context)
    }
}

/// EVM context handler.
pub trait Handler {
    const INSPECT: bool;
    /// Get global const context of evm execution
    fn env(&self) -> &Env;

    fn inspect(&mut self) -> &mut dyn Inspector;

    /// load account. Returns (is_cold,is_new_account)
    fn load_account(&mut self, address: H160) -> (bool, bool);
    /// Get environmental block hash.
    fn block_hash(&mut self, number: U256) -> H256;
    /// Get balance of address.
    fn balance(&mut self, address: H160) -> (U256, bool);
    /// Get code of address.
    fn code(&mut self, address: H160) -> (Bytes, bool);
    /// Get code hash of address.
    fn code_hash(&mut self, address: H160) -> (H256, bool);
    /// Get storage value of address at index.
    fn sload(&mut self, address: H160, index: H256) -> (H256, bool);
    /// Set storage value of address at index. Return if slot is cold/hot access.
    fn sstore(&mut self, address: H160, index: H256, value: H256) -> (H256, H256, H256, bool);
    /// Create a log owned by address with given topics and data.
    fn log(&mut self, address: H160, topics: Vec<H256>, data: Bytes);
    /// Mark an address to be deleted, with funds transferred to target.
    fn selfdestruct(&mut self, address: H160, target: H160) -> SelfDestructResult;
    /// Invoke a create operation.
    fn create<SPEC: Spec>(
        &mut self,
        caller: H160,
        scheme: CreateScheme,
        value: U256,
        init_code: Bytes,
        gas: u64,
    ) -> (ExitReason, Option<H160>, Gas, Bytes);

    /// Invoke a call operation.
    fn call<SPEC: Spec>(
        &mut self,
        code_address: H160,
        transfer: Transfer,
        input: Bytes,
        gas: u64,
        context: CallContext,
    ) -> (ExitReason, Gas, Bytes);
}
