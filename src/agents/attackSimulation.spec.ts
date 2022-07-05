import { createTransactionEvent, HandleTransaction, TransactionEvent } from 'forta-agent';
import { getEthersForkProvider } from '../utils/blockchain';
import attackSimAgent from './attackSimulation';

const mockNonAttacker = '0x1234567890123456789012345678901234567890';
const mockAttacker = '0x63341Ba917De90498F3903B199Df5699b4a55AC0'; // exploiter
const mockAttackerContract = '0x7336F819775B1D31Ea472681D70cE7A903482191'; // exploiter
const blockNumber = 14684300;
const chainId = 1;

describe.only('attack simulation', () => {
  let handleTx: HandleTransaction;
  let mockTxEvent: TransactionEvent;

  beforeAll(async () => {
    handleTx = attackSimAgent.provideHandleTx(chainId, getEthersForkProvider);
    mockTxEvent = createTransactionEvent({
      transaction: { from: mockAttacker },
      contractAddress: mockAttackerContract,
      block: { number: blockNumber },
    } as any);
  });

  describe('handleTransaction', () => {
    jest.setTimeout(40000);
    it('return empty finding if provided contract address is not actually a contract (0 code)', async () => {
      const mockTxEvent = createTransactionEvent({
        contractAddress: mockNonAttacker,
        transaction: { from: mockAttacker },
        block: { number: blockNumber },
      } as any);
      let findings = await handleTx(mockTxEvent);
      expect(findings).toStrictEqual([]);
    });

    it('returns empty finding if any balance change below the threshold occur', async () => {
      const mockTxEvent = createTransactionEvent({
        contractAddress: mockAttackerContract,
        transaction: { from: mockNonAttacker },
        block: { number: blockNumber },
      } as any);
      let findings = await handleTx(mockTxEvent);
      expect(findings).toStrictEqual([]);
    });

    // it('works', async () => {
    //   const findings = await handleTx(mockTxEvent);
    //   expect(true).toEqual(true);
    // });
  });
});
