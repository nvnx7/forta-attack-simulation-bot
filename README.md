# Attack Simulation Agent

## Description

This agent simulates an attack before it happens and raises alerts if the attack is detected.

## Supported Chains

- Ethereum

## Alerts

Alerts fired by agent:

- TORNADO_CASH_FUNDED_ADDRESS
  - Fired when an address is funded by Tornado Cash
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata
    - suspectedAccount: The address that was funded
- SUSPICIOUS_CONTRACT_CREATION
  - Fired when a contract is created by a tornado funded address
  - Severity is always set to "high"
  - Type is always set to "suspicious"
  - Metadata
    - suspiciousSender: The address that created the contract
    - suspiciousContract: The address of the contract that was created
- MALICIOUS_TRANSACTION_SIMULATION
  - Fired when a it is found that a suspected contract can drain high value funds - eth or any token
  - Severity is always set to "critical"
  - Type is always set to "exploit"
  - Metadata
    - attacker: The address that is attacking the contract
    - attackerContract: The address of the contract that is initiating the attack
    - token: The token address that is being drained or value - "native" if Ether is being drained
    - transferValue: The value that is being transferred

## Test Data

The agent behavior can be verified by running the agent through blocks 14684286 - where tornado funding is detected - and 14684300 - where suspicious contract creation is detected leading the bot to trigger simulation of any possible attack transaction. Simply run:

```
npm run range 14684286..14684300
```
