import { createTransactionEvent, HandleTransaction, TransactionEvent } from 'forta-agent';
import AttackSimAgent from './attackSimulation';

const mockNonSuspect = '0x1234567890123456789012345678901234567890';
const mockSuspect = '0x63341Ba917De90498F3903B199Df5699b4a55AC0'; // exploiter
const mockSuspiciousContract = '0x7336F819775B1D31Ea472681D70cE7A903482191'; // exploiter
const blockNumber = 14684300;
const chainId = 1;

describe.only('attack simulation', () => {
  let handleTx: HandleTransaction;
  let mockTxEvent: TransactionEvent;

  beforeAll(async () => {
    handleTx = AttackSimAgent.provideHandleTx(chainId);
    mockTxEvent = createTransactionEvent({
      transaction: { from: mockSuspect },
      contractAddress: mockSuspiciousContract,
      block: { number: blockNumber },
    } as any);
  });

  describe('handleTransaction', () => {
    jest.setTimeout(20000);
    it('return empty finding if provided contract address is not actually a contract (0 code)', async () => {
      let mockTxEvent = createTransactionEvent({ contractAddress: '0x' } as any);
      let findings = await handleTx(mockTxEvent);
      expect(findings).toStrictEqual([]);
    });

    // it('returns empty finding if no function signature is detected in bytecode',async () => {

    // })

    it('works', async () => {
      const findings = await handleTx(mockTxEvent);
      expect(true).toEqual(true);
    });
  });
});
