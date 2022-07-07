import {
  ethers,
  Finding,
  FindingSeverity,
  FindingType,
  HandleTransaction,
  Receipt,
  TransactionEvent,
} from 'forta-agent';
import { Contract } from 'ethers-multicall';

import { TOKEN_BALANCE_ABI } from '../utils/constants';
import {
  fuzzCalldatasForContract,
  GetEthersForkProvider,
  GetMultiCallProvider,
} from '../utils/blockchain';

const ALERT_ID = 'MALICIOUS_TRANSACTION_SIMULATION';

const provideHandleTx = (
  chainId: number,
  getEthersForkProvider: GetEthersForkProvider,
  getTxReceipt: (txHash: string) => Promise<Receipt>,
  getMultiCallProvider: GetMultiCallProvider,
  tokenDataToCheck: { address: string; alertDeltaThreshold: string }[],
): HandleTransaction => {
  return async function handleTx(txEvent: TransactionEvent) {
    const findings: Finding[] = [];
    // check for contract creation tx
    if (txEvent.to) {
      return findings;
    }

    // Extract the attacker and attacker contract addresses
    const attacker = txEvent.from.toLowerCase();
    const attackerContract = await getTxReceipt(txEvent.hash)
      .then((tx) => tx.contractAddress)
      .catch(() => {
        console.error(`Failed to get contract address for tx - ${txEvent.hash}`);
      });

    // make sure a contract creation happened
    if (!attackerContract) {
      return findings;
    }

    // Create a fork at this transaction's block number and proceed
    // with any attack simulation
    const blockNumber = txEvent.block.number;
    const provider = getEthersForkProvider(blockNumber, [attacker]);

    // Check if address is contract i.e. bytecode not empty
    const bytecode = await provider.getCode(attackerContract);
    if (bytecode === '0x') {
      return findings;
    }

    // Analyze bytecode to retrieve random calldatas (with valid function selectors)
    // for the purpose of fuzzing the malicious contract
    const fuzzedCalldatas = fuzzCalldatasForContract(bytecode, 3, 2);

    if (fuzzedCalldatas.length === 0) {
      return findings;
    }

    // Get Signer corresponding to the attacker to be used for sending attack tx
    const attackSigner = provider.getSigner(attacker);

    // Initialize MultiCall provider
    const multiCallProvider = getMultiCallProvider(provider, chainId);

    // Collect all balance call objects to use for a single batch call
    const attackerBalCalls: any = [];
    const attackerContractBalCalls: any = [];
    tokenDataToCheck.forEach((tok) => {
      if (!tok.address) {
        // Assume native eth
        attackerBalCalls.push(multiCallProvider.getEthBalance(attacker));
        attackerContractBalCalls.push(multiCallProvider.getEthBalance(attackerContract));
      } else {
        // A token
        const contract = new Contract(tok.address, [TOKEN_BALANCE_ABI]);
        attackerBalCalls.push(contract.balanceOf(attacker));
        attackerContractBalCalls.push(contract.balanceOf(attackerContract));
      }
    });

    // First half of the calls are of `attacker` address
    // Second half of the calls are of `attackerContract` address
    const allBalanceCalls = [...attackerBalCalls, ...attackerContractBalCalls];

    // Fetch all initial balances in a single call
    const startBalances = await multiCallProvider.all(allBalanceCalls);

    // Balance change thresholds to fire alerts
    const deltaThresholds = tokenDataToCheck.map((tok) =>
      ethers.utils.parseEther(tok.alertDeltaThreshold),
    );
    for (const calldata of fuzzedCalldatas) {
      try {
        await attackSigner.sendTransaction({
          to: attackerContract,
          data: `${calldata}`,
        });
      } catch (error) {
        // ignore errors/reverts
        continue;
      }

      // Fetch all balances after the call
      const endBalances = await multiCallProvider.all(allBalanceCalls);

      // Calculate all balance changes
      const deltas = startBalances.map((startBal, i) => endBalances[i].sub(startBal));

      // Check balance changes above threshold for `attacker` address
      const attackerDeltas = deltas.slice(0, deltas.length / 2);
      attackerDeltas.forEach((delta, i) => {
        if (delta.gte(deltaThresholds[i])) {
          const finding = Finding.fromObject({
            name: 'Potential High Value Transfer Exploit',
            description: `Potential high value drain detected from suspicious address - ${attacker}`,
            alertId: ALERT_ID,
            severity: FindingSeverity.Critical,
            type: FindingType.Exploit,
            metadata: {
              attacker,
              attackerContract,
              token: tokenDataToCheck[i].address || 'native',
              transferValue: delta.toString(),
            },
          });

          findings.push(finding);
        }
      });

      // Check balance changes above threshold for `attackerContract` address
      const attackerContractDeltas = deltas.slice(deltas.length / 2);
      attackerContractDeltas.forEach((delta, i) => {
        if (delta.gte(deltaThresholds[i])) {
          const finding = Finding.fromObject({
            name: 'Potential High Value Transfer Exploit',
            description: `Potential high value drain detected from suspicious address - ${attackerContract}`,
            alertId: ALERT_ID,
            severity: FindingSeverity.Critical,
            type: FindingType.Exploit,
            metadata: {
              attacker,
              attackerContract,
              token: tokenDataToCheck[i].address || 'native',
              transferValue: delta.toString(),
            },
          });

          findings.push(finding);
        }
      });

      // Stop fuzzing and report if any critical findings are discovered
      if (findings.length !== 0) break;
    }

    return findings;
  };
};

export default { ALERT_ID, provideHandleTx };
