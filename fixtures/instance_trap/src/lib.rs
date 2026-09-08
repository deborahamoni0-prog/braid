#![no_std]
//! Looks parallel-safe and is not: the keys are per-address, but they live in
//! instance storage, which is a single ledger entry.
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Deposit(Address),
}

#[contract]
pub struct InstanceTrap;

#[contractimpl]
impl InstanceTrap {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let prev: i128 = env.storage().instance().get(&DataKey::Deposit(user.clone())).unwrap_or(0);
        env.storage().instance().set(&DataKey::Deposit(user), &(prev + amount));
    }

    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let prev: i128 = env.storage().instance().get(&DataKey::Deposit(user.clone())).unwrap_or(0);
        env.storage().instance().set(&DataKey::Deposit(user), &(prev - amount));
    }
}
