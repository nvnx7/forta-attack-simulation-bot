import { ethers, getJsonRpcUrl } from 'forta-agent';
import Ganache from 'ganache';

/**
 * Create in-memory fork and return provider
 */
export type GetEthersForkProvider = (
  blockNumber: number,
  unlockedAddresses: string[],
) => ethers.providers.Web3Provider;
export const getEthersForkProvider: GetEthersForkProvider = (blockNumber, unlockedAccounts) => {
  return new ethers.providers.Web3Provider(
    Ganache.provider({
      fork: { url: getJsonRpcUrl(), blockNumber },
      wallet: { unlockedAccounts },
      logging: { quiet: true },
    }) as any,
  );
};

/**
 * Extracts 4-byte functions selectors from bytecode by matching following opcode seq.
 * DUP1
 * PUSH4 <4-byte function selector>
 * EQ
 * PUSH2 <jumpdest for the function>
 * JUMPI
 */
export const analyzeBytecode = (bytecode: string): string[] => {
  const funcSelectorPat = /8063([0-9a-fA-F]){8}1461([0-9a-fA-F]){4}57/gi;
  let matches = bytecode.match(funcSelectorPat);

  // Extract functions selectors from matched bytecode
  return matches?.map((match) => match.slice(4, 12)) || [];
};
