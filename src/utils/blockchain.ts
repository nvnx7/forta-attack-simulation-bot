import { ethers, getJsonRpcUrl } from 'forta-agent';
import { Provider as MultiCallProvider } from 'ethers-multicall';
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
 * Return the multi-call provider instance
 */
export type GetMultiCallProvider = (
  provider: ethers.providers.Web3Provider,
  chainId: number,
) => MultiCallProvider;
export const getMultiCallProvider: GetMultiCallProvider = (
  provider,
  chainId,
): MultiCallProvider => {
  return new MultiCallProvider(provider, chainId);
};

/**
 * Extracts 4-byte functions selectors from bytecode by matching following opcode seq.
 * DUP1
 * PUSH4 <4-byte function selector>
 * EQ
 * PUSH2 <jumpdest for the function>
 * JUMPI
 *
 * And then appends random calldata to the end of the function selectors
 * for the purpose of fuzzing
 */
export const retrieveRandomCalldatasForContract = (
  bytecode: string,
  num32ByteChunks: number = 3,
): string[] => {
  const funcSelectorPat = /8063([0-9a-fA-F]){8}1461([0-9a-fA-F]){4}57/gi;
  const matches = bytecode.match(funcSelectorPat);

  // Extract plain function selectors
  const funcSelectors = matches?.map((match) => '0x' + match.slice(4, 12)) || [];

  if (num32ByteChunks > 1) {
    // Extract functions selectors from matched bytecode
    return funcSelectors;
  }

  // Append random 32-byte chunks to detected function selectors for fuzzing.
  // NOTE: Appending any extra 32-byte chunks should not affect the functions
  // that expect any less-sized calldata. Any extra calldata should be simply
  // ignored by contract execution logic.
  const calldatas = [];
  for (const selector of funcSelectors) {
    let cd = selector;
    for (let i = 0; i < num32ByteChunks; i++) {
      cd += genRandomBytes(32);
    }
    calldatas.push(cd);
  }

  return calldatas;
};

const genRandomBytes = (size: number) =>
  [...Array(size * 2)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
