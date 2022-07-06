import LRUCache from 'lru-cache';
import {
  Finding,
  FindingSeverity,
  FindingType,
  HandleTransaction,
  Receipt,
  TransactionEvent,
} from 'forta-agent';

const ALERT_ID = 'SUSPICIOUS_CONTRACT_CREATION';

const provideHandleTx = (
  suspectsCache: LRUCache<string, undefined>,
  getTxReceipt: (txHash: string) => Promise<Receipt>,
): HandleTransaction => {
  return async function handleTx(txEvent: TransactionEvent) {
    const findings: Finding[] = [];

    // Determine if the tx sender has been flagged as tornado cash funded
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
    let suspiciousContract: string;
    try {
      suspiciousContract = (await getTxReceipt(txEvent.hash).then(
        (tx) => tx.contractAddress,
      )) as string;
    } catch (error) {
      console.error(`Error fetching ttx receipt for ${txEvent.hash}`);
      return findings;
    }

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
