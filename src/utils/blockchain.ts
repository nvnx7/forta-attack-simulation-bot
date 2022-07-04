// Pattern for matching following bytecode sequence:
// DUP1
// PUSH4 <4-byte function selector>
// EQ
// PUSH2 <jumpdest for the function>
// JUMPI
const funcSelectorPat = /8063([0-9a-fA-F]){8}1461([0-9a-fA-F]){4}57/gi;

/**
 * Extracts 4-byte functions selectors from bytecode.
 */
export const analyzeBytecode = (bytecode: string): string[] => {
  let matches = bytecode.match(funcSelectorPat);

  // Extract functions selectors from matched bytecode
  return matches?.map((match) => match.slice(4, 12)) || [];
};
