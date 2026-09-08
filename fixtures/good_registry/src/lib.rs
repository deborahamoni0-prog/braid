#![no_std]
//! The remediated version of `hot_counter`: identifiers are derived from data
//! the caller already supplies, so nothing shared is read or written.
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Job(BytesN<32>),
    OwnerIndex(Address),
}

#[contract]
pub struct GoodRegistry;

#[contractimpl]
impl GoodRegistry {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn register(env: Env, owner: Address, salt: BytesN<32>, label: String) {
        owner.require_auth();
        env.storage().persistent().set(&DataKey::Job(salt), &label);
        env.storage().persistent().set(&DataKey::OwnerIndex(owner), &0u32);
    }

    pub fn get(env: Env, id: BytesN<32>) -> Option<String> {
        env.storage().persistent().get(&DataKey::Job(id))
    }
}
