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
import { analyzeBytecode, GetEthersForkProvider, GetMultiCallProvider } from '../utils/blockchain';

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

    const blockNumber = txEvent.block.number;
    const provider = getEthersForkProvider(blockNumber, [attacker]);

    // Check if address is contract i.e. bytecode not empty
    const bytecode = await provider.getCode(attackerContract);
    if (bytecode === '0x') {
      return findings;
    }

    // Extract functions selectors from bytecode
    const functionsSelectors = analyzeBytecode(bytecode);
    if (functionsSelectors.length === 0) {
      return findings;
    }

    const signer = provider.getSigner(attacker);
    const multiCallProvider = getMultiCallProvider(provider, chainId);

    // Collect all balance call objects in a single batch call
    // const attackerBalCalls: any = [multiCallProvider.getEthBalance(attacker)];
    // const attackerContractBalCalls: any = [multiCallProvider.getEthBalance(attackerContract)];
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
    for (const selector of functionsSelectors) {
      try {
        await signer.sendTransaction({
          to: attackerContract,
          data: `0x${selector}`,
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
    }

    return findings;
  };
};

export default { ALERT_ID, provideHandleTx };
