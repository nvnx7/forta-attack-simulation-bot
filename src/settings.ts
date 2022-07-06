// Set values according to the need
export const tornadoFundedAccountsCacheLimit = 1000;

/**
 * Attack simulation agent checks these tokens (ERC20/ERC721/ERC1155) for any
 * balance change above the set threshold.
 *
 * NOTE: Empty address is assumed to be native eth token.
 * Threshold values do not include decimals
 */
export const tokenDataToCheckInSimulation = [
  // Native Eth
  { address: '', alertDeltaThreshold: '100' },
  // wETH
  { address: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', alertDeltaThreshold: '100' },
];
