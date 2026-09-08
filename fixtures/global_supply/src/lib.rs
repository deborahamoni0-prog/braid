#![no_std]
//! A single aggregate written on the hottest path in the contract.
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    TotalSupply,
    Balance(Address),
    FeeBps,
}

#[contract]
pub struct GlobalSupply;

#[contractimpl]
impl GlobalSupply {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let total: i128 = env.storage().persistent().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().persistent().set(&DataKey::TotalSupply, &(total + amount));

        let bal: i128 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(to), &(bal + amount));
    }

    pub fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let total: i128 = env.storage().persistent().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().persistent().set(&DataKey::TotalSupply, &(total - amount));

        let bal: i128 = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(from), &(bal - amount));
    }

    /// Read-only on the hot path: shared, but harmless.
    pub fn quote(env: Env, amount: i128) -> i128 {
        let fee: i128 = env.storage().persistent().get(&DataKey::FeeBps).unwrap_or(30);
        amount * fee / 10_000
    }

    pub fn set_fee(env: Env, admin: Address, bps: i128) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::FeeBps, &bps);
    }
}
