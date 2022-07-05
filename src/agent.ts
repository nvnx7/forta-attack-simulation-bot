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
import tornadoFundingAgent from './agents/tornadoFunding';
import suspiciousContractCreationAgent from './agents/suspiciousContract';
import attackSimulationAgent from './agents/attackSimulation';
import { TORNADO_FUNDED_ACCOUNT_CACHE_SIZE_LIMIT } from './utils/constants';
import { getEthersForkProvider } from './utils/blockchain';

// Cache of suspicious addresses
let cache: LRUCache<string, undefined>;

let tornadoFundingHandleTx: HandleTransaction;
let suspiciousContractHandleTx: HandleTransaction;
let attackSimulationHandleTx: HandleTransaction;

const initialize = async () => {
  const { chainId } = await getEthersProvider().getNetwork();
  cache = new LRUCache({ max: TORNADO_FUNDED_ACCOUNT_CACHE_SIZE_LIMIT });
  tornadoFundingHandleTx = tornadoFundingAgent.provideHandleTx(chainId, cache);
  suspiciousContractHandleTx = suspiciousContractCreationAgent.provideHandleTx(cache);
  attackSimulationHandleTx = attackSimulationAgent.provideHandleTx(chainId, getEthersForkProvider);
};

const handleTransaction: HandleTransaction = async (txEvent: TransactionEvent) => {
  const findings: Finding[] = [];

  // console.log({ txEvent });

  // check for flash-loan involvement (use lib?)
  // detect if created contract is trying to interact with target?
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

export default {
  initialize,
  handleTransaction,
};
