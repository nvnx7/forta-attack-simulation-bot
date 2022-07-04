const { ethers } = require('forta-agent');
const ganache = require('ganache');

const PORT = 8545;

/**
 * Starts a local fork of mainnet.
 */
async function runFork() {
  console.log('Starting fork from latest block number...');
  const provider = new ethers.providers.Web3Provider(ganache.provider());
  // const blockNumber = await provider.getBlockNumber();

  // const opts = {
  //   fork: {
  //     blockNumber: 'latest',
  //   }
  // }
  const server = ganache.server();
  server.listen(PORT, async (err) => {
    if (err) throw err;
    console.log(`ganache server started on port ${PORT}`);
  });
}

runFork();
