import {
  createTransactionEvent,
  Finding,
  FindingSeverity,
  FindingType,
  HandleTransaction,
} from 'forta-agent';
import LRUCache from 'lru-cache';
import suspiciousContractAgent from './suspiciousContract';

const mockNonAttacker = '0x1234567890123456789012345678901234567890';
const mockAttacker = '0xa234567890123456789012345678901234567890';
const mockAttackerContract = '0xc234567890123456789012345678901234567890';

describe.only('tornado cash funding agent', () => {
  let handleTx: HandleTransaction;
  let cache: LRUCache<string, undefined>;

  beforeAll(async () => {
    cache = new LRUCache({ max: 1000 });
    cache.set(mockAttacker.toLowerCase(), undefined);
    handleTx = suspiciousContractAgent.provideHandleTx(cache);
  });

  describe('handleTransaction', () => {
    it('returns empty finding if no tornado funded account (non - Attacker) involved', async () => {
      const mockTxEvent = createTransactionEvent({
        transaction: {
          hash: '0xa',
          from: mockNonAttacker,
          to: null,
        },
        contractAddress: mockAttackerContract,
      } as any);

      const findings = await handleTx(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it('returns empty finding if no contract creation involved', async () => {
      const mockTxEvent = createTransactionEvent({
        transaction: {
          from: mockAttacker,
          to: null,
        },
        contractAddress: mockAttackerContract,
      } as any);

      const findings = await handleTx(mockTxEvent);

      expect(cache.has(mockAttacker)).toStrictEqual(true);
      expect(findings).toHaveLength(1);
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: 'Suspicious Contract Creation',
          description: `Suspicious contract ${mockAttackerContract} created by the tornado cash funded address - ${mockAttacker}`,
          alertId: suspiciousContractAgent.ALERT_ID,
          severity: FindingSeverity.Medium,
          type: FindingType.Suspicious,
          metadata: {
            suspectedSender: mockAttacker,
            suspiciousContract: mockAttackerContract,
          },
        }),
      ]);
    });
  });
});
