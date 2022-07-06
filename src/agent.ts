import { Finding, HandleTransaction, TransactionEvent, getTransactionReceipt } from 'forta-agent';
import LRUCache from 'lru-cache';
import tornadoFundingAgent from './agents/tornadoFunding';
import suspiciousContractCreationAgent from './agents/suspiciousContract';
import attackSimulationAgent from './agents/attackSimulation';
import { getEthersForkProvider, getMultiCallProvider } from './utils/blockchain';
import { tokenDataToCheckInSimulation, tornadoFundedAccountsCacheLimit } from './settings';

let chainId: number = 1;
// Cache of suspicious addresses
let cache: LRUCache<string, undefined> = new LRUCache({ max: tornadoFundedAccountsCacheLimit });

const provideHandleTx = (
  tornadoFundingHandleTx: HandleTransaction,
  suspiciousContractHandleTx: HandleTransaction,
  attackSimulationHandleTx: HandleTransaction,
): HandleTransaction => {
  return async function handleTx(txEvent: TransactionEvent) {
    const findings: Finding[] = [];

    const tornadoFindings = await tornadoFundingHandleTx(txEvent);
    findings.push(...tornadoFindings);
    const suspiciousContractFindings = await suspiciousContractHandleTx(txEvent);
    findings.push(...suspiciousContractFindings);

    if (suspiciousContractFindings.length > 0) {
      const simulationFindings = await attackSimulationHandleTx(txEvent);
      findings.push(...simulationFindings);
    }
    return findings;
  };
};

export default {
  provideHandleTx,
  handleTransaction: provideHandleTx(
    tornadoFundingAgent.provideHandleTx(chainId, cache),
    suspiciousContractCreationAgent.provideHandleTx(cache, getTransactionReceipt),
    attackSimulationAgent.provideHandleTx(
      chainId,
      getEthersForkProvider,
      getTransactionReceipt,
      getMultiCallProvider,
      tokenDataToCheckInSimulation,
    ),
  ),
};
