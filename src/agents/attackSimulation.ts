import {
  ethers,
  Finding,
  FindingSeverity,
  FindingType,
  getTransactionReceipt,
  HandleTransaction,
  TransactionEvent,
} from 'forta-agent';
import { Contract, Provider } from 'ethers-multicall';

import {
  ETH_DELTA_THRESHOLD,
  TOKEN_ADDRESSES_TO_CHECK,
  TOKEN_BALANCE_ABI,
} from '../utils/constants';
import { analyzeBytecode, GetEthersForkProvider } from '../utils/blockchain';

const ALERT_ID = 'MALICIOUS_TRANSACTION_SIMULATION';

const ethDeltaThreshold = ethers.utils.parseEther(`${ETH_DELTA_THRESHOLD}`);
const tokenDeltaThresholds = TOKEN_ADDRESSES_TO_CHECK.map((v) =>
  ethers.utils.parseEther(`${v.alertDeltaThreshold}`),
);
const deltaThresholds = [ethDeltaThreshold, ...tokenDeltaThresholds];

const provideHandleTx = (
  chainId: number,
  getEthersForkProvider: GetEthersForkProvider,
): HandleTransaction => {
  return async function handleTx(txEvent: TransactionEvent) {
    const findings: Finding[] = [];

    const attacker = txEvent.from.toLowerCase();
    const attackerContract = await getTransactionReceipt(txEvent.hash)
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

    const signer = provider.getSigner(attacker);

    // Check if address is contract
    const bytecode = await provider.getCode(attackerContract);

    if (bytecode === '0x') {
      return findings;
    }

    // Extract functions selectors from bytecode
    const functionsSelectors = analyzeBytecode(bytecode);

    if (functionsSelectors.length === 0) {
      return findings;
    }

    const multiCallProvider = new Provider(provider, chainId);

    const ethBalanceCall = multiCallProvider.getEthBalance(attacker);
    const tokenBalanceCalls = TOKEN_ADDRESSES_TO_CHECK.map((v) => {
      const contract = new Contract(v.address, [TOKEN_BALANCE_ABI]);
      return contract.balanceOf(attacker);
    });
    const balanceCalls = [ethBalanceCall, ...tokenBalanceCalls];

    const startBalances = await multiCallProvider.all(balanceCalls);
    for (const selector of functionsSelectors.slice(1)) {
      await signer
        .sendTransaction({
          to: attackerContract,
          data: `0x${selector}`,
        })
        // ignore reverts
        .catch(() => {});

      const endBalances = await multiCallProvider.all(balanceCalls);

      // Asses balance changes and report findings
      const deltas = startBalances.map((startBal, i) => endBalances[i].sub(startBal));
      deltas.forEach((delta, i) => {
        if (delta.gte(deltaThresholds[i])) {
          const finding = Finding.fromObject({
            name: 'Suspicious High Value Transfer',
            description: `High value transfer detected from suspicious address - ${attacker}`,
            alertId: ALERT_ID,
            severity: FindingSeverity.Critical,
            type: FindingType.Exploit,
            metadata: {
              attacker,
              attackerContract,
              token: i === 0 ? 'native' : TOKEN_ADDRESSES_TO_CHECK[i - 1].address,
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
