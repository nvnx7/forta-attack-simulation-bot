import LRUCache from 'lru-cache';
import {
  Finding,
  FindingSeverity,
  FindingType,
  getTransactionReceipt,
  HandleTransaction,
  TransactionEvent,
} from 'forta-agent';

const ALERT_ID = 'SUSPICIOUS_CONTRACT_CREATION';

const provideHandleTx = (suspectsCache: LRUCache<string, undefined>): HandleTransaction => {
  return async function handleTx(txEvent: TransactionEvent) {
    const findings: Finding[] = [];

    const sender = txEvent.from.toLowerCase();
    const isSenderSuspected = suspectsCache.has(sender);

    if (!isSenderSuspected) {
      return findings;
    }

    // Detect contract creation
    const isContractCreation = !txEvent.to;
    if (!isContractCreation) {
      return findings;
    }

    // Fetch created contract and report back
    const suspiciousContract = (await getTransactionReceipt(txEvent.hash).then(
      (tx) => tx.contractAddress,
    )) as string;

    findings.push(
      Finding.fromObject({
        name: 'Suspicious Contract Creation',
        description: `Suspicious contract ${suspiciousContract} created by the tornado cash funded address - ${sender}`,
        alertId: ALERT_ID,
        severity: FindingSeverity.Medium,
        type: FindingType.Suspicious,
        metadata: {
          suspectedSender: sender,
          suspiciousContract,
        },
      }),
    );

    return findings;
  };
};

export default { provideHandleTx, ALERT_ID };