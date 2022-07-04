import {
  FindingType,
  FindingSeverity,
  Finding,
  HandleTransaction,
  createTransactionEvent,
  ethers,
} from 'forta-agent';
import agent from './agent';

describe('high tether transfer agent', () => {
  let handleTx: HandleTransaction;
  const mockTxEvent = createTransactionEvent({} as any);

  beforeAll(() => {
    handleTx = agent.handleTransaction;
  });

  describe('handleTransaction', () => {
    it('returns empty findings if there are no Tether transfers', async () => {
      mockTxEvent.filterLog = jest.fn().mockReturnValue([]);

      const findings = await handleTx(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });
  });
});
