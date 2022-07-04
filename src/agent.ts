import {
  BlockEvent,
  Finding,
  HandleBlock,
  HandleTransaction,
  TransactionEvent,
  FindingSeverity,
  FindingType,
  getEthersProvider,
} from 'forta-agent';
import LRUCache from 'lru-cache';
import TornadoFundingAgent from './agents/tornadoFunding';
import SuspiciousContractCreationAgent from './agents/contractCreation';
import AttackSimulationAgent from './agents/attackSimulation';
import { TORNADO_FUNDED_ACCOUNT_CACHE_SIZE_LIMIT } from './utils/constants';

// Cache of suspicious addresses
let cache: LRUCache<string, undefined>;

let tornadoFundingHandleTx: HandleTransaction;
let suspiciousContractHandleTx: HandleTransaction;
let attackSimulationHandleTx: HandleTransaction;

const initialize = async () => {
  const { chainId } = await getEthersProvider().getNetwork();
  cache = new LRUCache({ max: TORNADO_FUNDED_ACCOUNT_CACHE_SIZE_LIMIT });
  tornadoFundingHandleTx = TornadoFundingAgent.provideHandleTx(chainId, cache);
  suspiciousContractHandleTx = SuspiciousContractCreationAgent.provideHandleTx(cache);
  attackSimulationHandleTx = AttackSimulationAgent.provideHandleTx(chainId);
};

const handleTransaction: HandleTransaction = async (txEvent: TransactionEvent) => {
  const findings: Finding[] = [];

  // check for flash-loan involvement (use lib?)
  // detect if created contract is trying to interact with target?
  const tornadoFindings = await tornadoFundingHandleTx(txEvent);
  const suspiciousContractFindings = await suspiciousContractHandleTx(txEvent);

  if (suspiciousContractFindings.length > 0) {
    const simulationFindings = await attackSimulationHandleTx(txEvent);
    findings.push(...simulationFindings);
  }

  return findings;
};

export default {
  initialize,
  handleTransaction,
};
