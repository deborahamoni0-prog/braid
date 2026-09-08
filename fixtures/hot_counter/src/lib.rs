#![no_std]
//! The sequence-counter trap: ids look parameterised, but minting one reads and
//! bumps a single shared entry, so every caller serialises on it.
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Seq,
    Job(u64),
    OwnerJobs(Address),
}

#[contracttype]
#[derive(Clone)]
pub struct Job {
    pub owner: Address,
    pub label: String,
}

#[contract]
pub struct HotCounter;

#[contractimpl]
impl HotCounter {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Seq, &0u64);
    }

    /// Every caller reads Seq, bumps Seq, then writes Job(id).
    pub fn create_job(env: Env, owner: Address, label: String) -> u64 {
        owner.require_auth();

        let id: u64 = env.storage().persistent().get(&DataKey::Seq).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Seq, &(id + 1));

        let job = Job { owner: owner.clone(), label };
        env.storage().persistent().set(&DataKey::Job(id), &job);
        env.storage().persistent().set(&DataKey::OwnerJobs(owner), &id);
        id
    }

    pub fn get_job(env: Env, id: u64) -> Option<Job> {
        env.storage().persistent().get(&DataKey::Job(id))
    }
}
