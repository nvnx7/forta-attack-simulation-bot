import { FindingType, FindingSeverity, Finding } from 'forta-agent';
import agent from './agent';

const mockNoFindingHandleTx = jest.fn().mockResolvedValue([]);
const mockFinding = Finding.fromObject({
  alertId: 'dummy-alert-id',
  name: 'Dummy',
  description: 'Dummy description',
  severity: FindingSeverity.High,
  type: FindingType.Exploit,
});

describe('Agent', () => {
  describe('handleTransaction', () => {
    it('returns empty finding if no suspicious contract was found', async () => {
      const mockAttackSimHandleTx = jest.fn();
      const handleTx = agent.provideHandleTx(
        mockNoFindingHandleTx,
        mockNoFindingHandleTx,
        mockAttackSimHandleTx,
      );

      const findings = await handleTx({} as any);
      expect(findings).toStrictEqual([]);
      expect(mockNoFindingHandleTx).toHaveBeenCalledTimes(2);
      expect(mockAttackSimHandleTx).toHaveBeenCalledTimes(0);
    });

    it('runs the simulation if non-empty suspicious contract finding is detected and returns any attack findings', async () => {
      const mockAttackSimHandleTx = jest.fn().mockResolvedValue([mockFinding]);
      const handleTx = agent.provideHandleTx(
        mockNoFindingHandleTx,
        jest.fn().mockResolvedValue([mockFinding]),
        mockAttackSimHandleTx,
      );

      const findings = await handleTx({} as any);

      // One finding is for suspicious contract creation detection
      // One finding is for simulation that was triggered by that suspicious contract creation
      expect(findings).toHaveLength(2);
      expect(findings).toStrictEqual([mockFinding, mockFinding]);
    });
  });
});
