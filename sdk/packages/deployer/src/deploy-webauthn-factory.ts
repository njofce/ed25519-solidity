import 'dotenv/config'
import WEB_AUTHN_ACCOUNT_FACTORY_DATA from './abis/WebAuthnAccountFactory.json';

import { createPublicClient, createWalletClient, custom } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { polygonMumbai, sepolia } from 'viem/chains'
import { http } from 'viem'

const walletClient = createWalletClient({
  chain: polygonMumbai,
  transport: http(process.env.RPC_URL) 
})

const publicClient = createPublicClient({
  chain: polygonMumbai,
  transport: http(process.env.RPC_URL) 
})


const account = privateKeyToAccount(process.env.ACCOUNT_PK as `0x${string}`)

export async function main() {

    console.log('Deploying WebAuthnAccountFactory...');

    
    const hash = await walletClient.deployContract({
        abi: WEB_AUTHN_ACCOUNT_FACTORY_DATA.abi,
        account,
        args: [
            process.env.ENTRYPOINT_ADDRESS
        ],
        bytecode: WEB_AUTHN_ACCOUNT_FACTORY_DATA.bytecode.object as `0x${string}`
    })
  
    console.log('TX hash', hash);
    console.log('Deployed WebAuthnAccountFactory, awaiting confirmation...');
  
    const txReceipt = await publicClient.waitForTransactionReceipt({
        hash: hash,
        confirmations: 1
    })


    console.log("WebAuthnAccountFactory deployed at: ", txReceipt.contractAddress);

}

main()
