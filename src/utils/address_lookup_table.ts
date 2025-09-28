import { 
  Connection, 
  PublicKey
} from '@solana/web3.js';

/**
 * Helper function to use an existing ALT (recommended for production)
 * Use create_alt.ts to create the ALT once, then hardcode the address and use this function
 */
export async function useExistingALT(
  connection: Connection,
  altAddress: PublicKey
): Promise<{ value: any } | null> {
  try {
    console.log(`Using existing ALT: ${altAddress.toString()}`);
    const altAccount = await connection.getAddressLookupTable(altAddress);
    
    if (altAccount.value) {
      console.log(`✅ ALT found with ${altAccount.value.state.addresses.length} addresses`);
    } else {
      console.log('❌ ALT not found');
    }
    
    return altAccount;
  } catch (error) {
    console.error('Error getting existing ALT:', error);
    return null;
  }
} 