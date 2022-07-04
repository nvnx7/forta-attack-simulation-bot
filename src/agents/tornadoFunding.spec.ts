import {
  createTransactionEvent,
  ethers,
  Finding,
  FindingSeverity,
  FindingType,
  HandleTransaction,
  TransactionEvent,
} from 'forta-agent';
import LRUCache from 'lru-cache';
import { TORNADO_ADDRESSES_BY_CHAIN_ID, TORNADO_WITHDRAW_EVENT_ABI } from '../utils/constants';
import TornadoFundingAgent from './tornadoFunding';

const mockAddress = '0x1234567890123456789012345678901234567890';
const chainId = 1;
const tornadoCashAddresses = TORNADO_ADDRESSES_BY_CHAIN_ID[chainId];

describe.only('tornado cash funding agent', () => {
  let handleTx: HandleTransaction;
  let cache: LRUCache<string, undefined>;
  let mockTxEvent: TransactionEvent;

  beforeAll(async () => {
    cache = new LRUCache({ max: 100 });
    handleTx = TornadoFundingAgent.provideHandleTx(chainId, cache);
    mockTxEvent = createTransactionEvent({} as any);
  });

  afterEach(() => {
    cache.clear();
  });

  describe('handleTransaction', () => {
    it('returns empty finding if no tornado cash withdraw occurred', async () => {
      mockTxEvent.filterLog = jest.fn().mockReturnValue([]);

      const findings = await handleTx(mockTxEvent);

      expect(findings).toStrictEqual([]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(1);
      expect(mockTxEvent.filterLog).toHaveBeenCalledWith(
        TORNADO_WITHDRAW_EVENT_ABI,
        TORNADO_ADDRESSES_BY_CHAIN_ID[chainId],
      );
    });

    it('returns finding if tornado cash withdraw occurred and caches suspected address', async () => {
      mockTxEvent.filterLog = jest.fn().mockReturnValue([
        {
          args: {
            from: tornadoCashAddresses[0],
            to: mockAddress,
            value: ethers.utils.parseEther('10'),
          },
        },
      ]);

      const findings = await handleTx(mockTxEvent);

      expect(findings).toHaveLength(1);
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: 'Tornado Cash Funded Address',
          description: `Tornado Cash funded address ${mockAddress}`,
          alertId: TornadoFundingAgent.ALERT_ID,
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            suspectedAccount: mockAddress,
          },
        }),
      ]);
      expect(cache.has(mockAddress)).toStrictEqual(true);
    });
  });
});
