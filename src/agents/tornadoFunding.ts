import {
  Finding,
  FindingSeverity,
  FindingType,
  HandleTransaction,
  TransactionEvent,
} from 'forta-agent';
import LRUCache from 'lru-cache';
import { TORNADO_ADDRESSES_BY_CHAIN_ID, TORNADO_WITHDRAW_EVENT_ABI } from '../utils/constants';

const ALERT_ID = 'TORNADO_CASH_FUNDED_ADDRESS';

/**
 * Provides bot handler for detecting and caching tornado cash funded addresses.
 */
const provideHandleTx = (
  chainId: number,
  suspectsCache: LRUCache<string, undefined>,
): HandleTransaction => {
  const tornadoCashAddresses = TORNADO_ADDRESSES_BY_CHAIN_ID[chainId];

  return async function handleTx(txEvent: TransactionEvent) {
    const findings: Finding[] = [];

    const tornadoWithdrawLogs = txEvent.filterLog(TORNADO_WITHDRAW_EVENT_ABI, tornadoCashAddresses);

    for (const log of tornadoWithdrawLogs) {
      const suspect = log.args.to as string;
      if (!suspect) continue;
      findings.push(
        Finding.fromObject({
          name: 'Tornado Cash Funded Address',
          description: `Tornado Cash funded address ${suspect}`,
          alertId: ALERT_ID,
          severity: FindingSeverity.Low,
          type: FindingType.Info,
          metadata: {
            suspectedAccount: suspect,
          },
        }),
      );

      suspectsCache.set(suspect.toLowerCase(), undefined); // only need to store key
    }

    return findings;
  };
};

export default { provideHandleTx, ALERT_ID };
