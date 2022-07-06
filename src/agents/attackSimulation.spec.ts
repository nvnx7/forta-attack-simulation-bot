import { createTransactionEvent, ethers, Finding, FindingSeverity, FindingType } from 'forta-agent';
import { getEthersForkProvider } from '../utils/blockchain';
import attackSimAgent from './attackSimulation';

const mockAttacker = '0x63341ba917de90498f3903b199df5699b4a55ac0';
const mockAttackerContract = '0x7336f819775b1d31ea472681d70ce7a903482191';
const mockBytecode = '0x8063af8271f71461abcd57';
const mockTokenDataToCheck = [
  { address: '', alertDeltaThreshold: '100' }, // Assumes native ETH if address is empty
  { address: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', alertDeltaThreshold: '100' }, // WETH
];
const blockNumber = 14684300;
const chainId = 1;

const zero = ethers.utils.parseEther('0');
const twoHundred = ethers.utils.parseEther('200');

describe.only('attack simulation', () => {
  describe('handleTransaction', () => {
    jest.setTimeout(40000);
    it('return empty finding if tx is not actually contract creation tx', async () => {
      const mockGetTxReceipt = jest.fn().mockResolvedValue({ contractAddress: null });
      const mockGetMultiCallProvider = jest.fn();
      const handleTx = attackSimAgent.provideHandleTx(
        chainId,
        getEthersForkProvider,
        mockGetTxReceipt,
        mockGetMultiCallProvider,
        mockTokenDataToCheck,
      );
      const mockTxEvent = createTransactionEvent({
        transaction: { from: mockAttacker },
        block: { number: blockNumber },
      } as any);
      let findings = await handleTx(mockTxEvent);
      expect(findings).toStrictEqual([]);
    });

    it('returns empty finding if any balance change below the threshold occur', async () => {
      const mockTxEvent = createTransactionEvent({
        transaction: { from: mockAttacker, to: null },
        block: { number: blockNumber },
      } as any);

      const mockGetTxReceipt = jest
        .fn()
        .mockResolvedValue({ contractAddress: mockAttackerContract });
      const mockGetMultiCallProvider = jest.fn().mockReturnValue({
        getEthBalance: jest.fn(),
        all: jest.fn().mockResolvedValueOnce([zero, zero]).mockResolvedValue([zero, zero]),
      });
      const mockGetEthersForkProvider = jest.fn().mockReturnValue({
        getCode: jest.fn().mockResolvedValue(mockBytecode),
        getSigner: jest.fn().mockReturnValue({
          sendTransaction: jest.fn().mockResolvedValue({}),
        }),
      });
      const handleTx = attackSimAgent.provideHandleTx(
        chainId,
        mockGetEthersForkProvider,
        mockGetTxReceipt,
        mockGetMultiCallProvider,
        mockTokenDataToCheck,
      );
      let findings = await handleTx(mockTxEvent);
      expect(findings).toStrictEqual([]);
    });

    it('raises alert if detects large amount of transfers', async () => {
      const mockTxEvent = createTransactionEvent({
        transaction: { from: mockAttacker, to: null },
        block: { number: blockNumber },
      } as any);

      const mockGetTxReceipt = jest
        .fn()
        .mockResolvedValue({ contractAddress: mockAttackerContract });
      const mockGetMultiCallProvider = jest.fn().mockReturnValue({
        getEthBalance: jest.fn(),
        all: jest
          .fn()
          // Set mock values such that only the attacker's balance of the token(weth)
          // hits the threshold
          .mockResolvedValueOnce([zero, zero, zero, zero])
          .mockResolvedValue([zero, twoHundred, zero, zero]),
      });
      const mockGetEthersForkProvider = jest.fn().mockReturnValue({
        getCode: jest.fn().mockResolvedValue(mockBytecode),
        getSigner: jest.fn().mockReturnValue({
          sendTransaction: jest.fn().mockResolvedValue({}),
        }),
      });
      const handleTx = attackSimAgent.provideHandleTx(
        chainId,
        mockGetEthersForkProvider,
        mockGetTxReceipt,
        mockGetMultiCallProvider,
        mockTokenDataToCheck,
      );
      let findings = await handleTx(mockTxEvent);
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: 'Potential High Value Transfer Exploit',
          description: `Potential high value drain detected from suspicious address - ${mockAttacker}`,
          alertId: attackSimAgent.ALERT_ID,
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            attacker: mockAttacker,
            attackerContract: mockAttackerContract,
            token: mockTokenDataToCheck[1].address,
            transferValue: twoHundred.toString(),
          },
        }),
      ]);
    });
  });
});
