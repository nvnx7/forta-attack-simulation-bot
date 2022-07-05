import {
  FindingType,
  FindingSeverity,
  Finding,
  HandleTransaction,
  createTransactionEvent,
  ethers,
} from 'forta-agent';
import agent from './agent';
import { TORNADO_ADDRESSES_BY_CHAIN_ID } from './utils/constants';

// Saddle Finance exploit blocks
const tornadoFundBlock = 14684286;
const contractCreationBlock = 14684300;
const attackBlock = 14684307;
const chainId = 1;
const tornadoCashAddresses = TORNADO_ADDRESSES_BY_CHAIN_ID[chainId];

const mockAttacker = '0x63341Ba917De90498F3903B199Df5699b4a55AC0';
const mockAttackerContract = '0x7336F819775B1D31Ea472681D70cE7A903482191';

const mockTornadoFundTx = createTransactionEvent({} as any);
mockTornadoFundTx.filterLog = jest.fn().mockReturnValue([
  {
    args: {
      from: tornadoCashAddresses[0],
      to: mockAttacker,
      value: ethers.utils.parseEther('10'),
    },
  },
]);
const mockSuspiciousContractCreationTx = createTransactionEvent({
  transaction: {
    from: mockAttacker,
    to: null,
  },
  contractAddress: mockAttackerContract,
} as any);
// console.log({ mockSuspiciousContractCreationTx });

describe('Agent', () => {
  let handleTx: HandleTransaction;
  // const mockTxEvent = createTransactionEvent({} as any);

  beforeAll(() => {
    handleTx = agent.handleTransaction;
  });

  describe('handleTransaction', () => {
    it('works', async () => {
      await agent.initialize();
      const tornadoFindings = await handleTx(mockTornadoFundTx);
      console.log({ mockSuspiciousContractCreationTx });

      const suspiciousContractFindings = await handleTx(mockSuspiciousContractCreationTx);
      console.log({ suspiciousContractFindings, tornadoFindings });
    });
  });
});
