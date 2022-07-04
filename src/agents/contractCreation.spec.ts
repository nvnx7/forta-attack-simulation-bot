import {
  createTransactionEvent,
  Finding,
  FindingSeverity,
  FindingType,
  HandleTransaction,
} from 'forta-agent';
import LRUCache from 'lru-cache';
import SuspiciousContractAgent from './contractCreation';

const mockNonSuspect = '0x1234567890123456789012345678901234567890';
const mockSuspect = '0xa234567890123456789012345678901234567890';
const mockSuspiciousContract = '0xc234567890123456789012345678901234567890';

describe.only('tornado cash funding agent', () => {
  let handleTx: HandleTransaction;
  let cache: LRUCache<string, undefined>;

  beforeAll(async () => {
    cache = new LRUCache({ max: 1000 });
    cache.set(mockSuspect.toLowerCase(), undefined);
    handleTx = SuspiciousContractAgent.provideHandleTx(cache);
  });

  describe('handleTransaction', () => {
    it('returns empty finding if no tornado funded account (non - suspect) involved', async () => {
      const mockTxEvent = createTransactionEvent({
        transaction: {
          hash: '0xa',
          from: mockNonSuspect,
          to: null,
        },
        contractAddress: mockSuspiciousContract,
      } as any);

      const findings = await handleTx(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it('returns empty finding if no contract creation involved', async () => {
      const mockTxEvent = createTransactionEvent({
        transaction: {
          hash: '0xa',
          from: mockSuspect,
          to: null,
        },
        contractAddress: mockSuspiciousContract,
      } as any);

      const findings = await handleTx(mockTxEvent);

      expect(cache.has(mockSuspect)).toStrictEqual(true);
      expect(findings).toHaveLength(1);
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: 'Suspicious Contract Creation',
          description: `Suspicious contract ${mockSuspiciousContract} created by the tornado cash funded address - ${mockSuspect}`,
          alertId: SuspiciousContractAgent.ALERT_ID,
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            suspectedSender: mockSuspect,
            suspiciousContract: mockSuspiciousContract,
          },
        }),
      ]);
    });
  });
});
