/**
 * ZK Proof Generation Utilities
 * 
 * This file provides functions for generating zero-knowledge proofs for privacy-preserving 
 * transactions on Solana. It handles both snarkjs and zkutil proof generation workflows.
 * 
 * Inspired by: https://github.com/tornadocash/tornado-nova/blob/f9264eeffe48bf5e04e19d8086ee6ec58cdf0d9e/src/prover.js
 */

/// <reference types="node" />

import * as anchor from "@coral-xyz/anchor";
import { wtns, groth16 } from 'snarkjs'
import { FIELD_SIZE } from './constants.js'

// @ts-ignore - ignore TypeScript errors for ffjavascript
import { utils } from 'ffjavascript'

// Type definitions for external modules
type WtnsModule = {
  debug: (input: any, wasmFile: string, wtnsFile: string, symFile: string, options: any, logger: any) => Promise<void>
  exportJson: (wtnsFile: string) => Promise<any>
}

type Groth16Module = {
  fullProve: (
    input: any,
    wasmFile: string,
    zkeyFile: string,
    logger?: any,
    wtnsCalcOptions?: { singleThread?: boolean },
    proverOptions?: { singleThread?: boolean }
  ) => Promise<{ proof: Proof; publicSignals: string[] }>
  verify: (vkeyData: any, publicSignals: any, proof: Proof) => Promise<boolean>
}

type UtilsModule = {
  stringifyBigInts: (obj: any) => any
  unstringifyBigInts: (obj: any) => any
}

// Cast imported modules to their types
const wtnsTyped = wtns as unknown as WtnsModule
const groth16Typed = groth16 as unknown as Groth16Module
const utilsTyped = utils as unknown as UtilsModule


// Define interfaces for the proof structures
interface Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

interface ProofResult {
  proof: Proof
}

/**
 * Generates a ZK proof using snarkjs and formats it for use on-chain
 *
 * @param input The circuit inputs to generate a proof for
 * @param keyBasePath The base path for the circuit keys (.wasm and .zkey files)
 * @param options Optional proof generation options (e.g., singleThread for Deno/Bun)
 * @returns A proof object with formatted proof elements and public signals
 */
async function prove(input: any, keyBasePath: string, options?: { singleThread?: boolean }): Promise<{
  proof: Proof
  publicSignals: string[];
}> {
  // Detect if we should use single-threaded mode (for Deno/Bun compatibility)
  const useSingleThread = options?.singleThread ?? shouldUseSingleThread();

  // Single-thread options need to be passed to BOTH witness calculation AND proving
  const singleThreadOpts = useSingleThread ? { singleThread: true } : undefined;

  // Call fullProve with all parameters:
  // 1. input, 2. wasmFile, 3. zkeyFile, 4. logger, 5. wtnsCalcOptions, 6. proverOptions
  return await groth16Typed.fullProve(
    utilsTyped.stringifyBigInts(input),
    `${keyBasePath}.wasm`,
    `${keyBasePath}.zkey`,
    undefined, // logger parameter
    singleThreadOpts, // wtnsCalcOptions (5th param) - for witness calculation
    singleThreadOpts  // proverOptions (6th param) - for proving
  )
}

/**
 * Detect if single-threaded mode should be used
 */
function shouldUseSingleThread(): boolean {
  // @ts-ignore - Deno global
  if (typeof Deno !== 'undefined') {
    return true; // Deno has worker issues
  }
  // @ts-ignore - Bun global
  if (typeof Bun !== 'undefined') {
    return true; // Bun may have worker issues
  }
  return false;
}

export function parseProofToBytesArray(
  proof: Proof,
  compressed: boolean = false,
): {
  proofA: number[];
  proofB: number[][];
  proofC: number[];
} {
  const proofJson = JSON.stringify(proof, null, 1);
  const mydata = JSON.parse(proofJson.toString());
  try {
    for (const i in mydata) {
      if (i == "pi_a" || i == "pi_c") {
        for (const j in mydata[i]) {
          mydata[i][j] = Array.from(
            utils.leInt2Buff(utils.unstringifyBigInts(mydata[i][j]), 32),
          ).reverse();
        }
      } else if (i == "pi_b") {
        for (const j in mydata[i]) {
          for (const z in mydata[i][j]) {
            mydata[i][j][z] = Array.from(
              utils.leInt2Buff(utils.unstringifyBigInts(mydata[i][j][z]), 32),
            );
          }
        }
      }
    }

    if (compressed) {
      const proofA = mydata.pi_a[0];
      // negate proof by reversing the bitmask
      const proofAIsPositive = yElementIsPositiveG1(
        new anchor.BN(mydata.pi_a[1]),
      )
        ? false
        : true;
      proofA[0] = addBitmaskToByte(proofA[0], proofAIsPositive);
      const proofB = mydata.pi_b[0].flat().reverse();
      const proofBY = mydata.pi_b[1].flat().reverse();
      const proofBIsPositive = yElementIsPositiveG2(
        new anchor.BN(proofBY.slice(0, 32)),
        new anchor.BN(proofBY.slice(32, 64)),
      );
      proofB[0] = addBitmaskToByte(proofB[0], proofBIsPositive);
      const proofC = mydata.pi_c[0];
      const proofCIsPositive = yElementIsPositiveG1(
        new anchor.BN(mydata.pi_c[1]),
      );
      proofC[0] = addBitmaskToByte(proofC[0], proofCIsPositive);
      return {
        proofA,
        proofB,
        proofC,
      };
    }
    return {
      proofA: [mydata.pi_a[0], mydata.pi_a[1]].flat(),
      proofB: [
        mydata.pi_b[0].flat().reverse(),
        mydata.pi_b[1].flat().reverse(),
      ].flat(),
      proofC: [mydata.pi_c[0], mydata.pi_c[1]].flat(),
    };
  } catch (error: any) {
    console.error("Error while parsing the proof.", error.message);
    throw error;
  }
}

// mainly used to parse the public signals of groth16 fullProve
export function parseToBytesArray(publicSignals: string[]): number[][] {
  const publicInputsJson = JSON.stringify(publicSignals, null, 1);
  const publicInputsBytesJson = JSON.parse(publicInputsJson.toString());
  try {
    const publicInputsBytes = new Array<Array<number>>();
    for (const i in publicInputsBytesJson) {
      const ref: Array<number> = Array.from([
        ...utils.leInt2Buff(utils.unstringifyBigInts(publicInputsBytesJson[i]), 32),
      ]).reverse();
      publicInputsBytes.push(ref);
    }

    return publicInputsBytes;
  } catch (error: any) {
    console.error("Error while parsing public inputs.", error.message);
    throw error;
  }
}

function yElementIsPositiveG1(yElement: anchor.BN): boolean {
  return yElement.lte(FIELD_SIZE.sub(yElement));
}

function yElementIsPositiveG2(yElement1: anchor.BN, yElement2: anchor.BN): boolean {
  const fieldMidpoint = FIELD_SIZE.div(new anchor.BN(2));

  // Compare the first component of the y coordinate
  if (yElement1.lt(fieldMidpoint)) {
    return true;
  } else if (yElement1.gt(fieldMidpoint)) {
    return false;
  }

  // If the first component is equal to the midpoint, compare the second component
  return yElement2.lt(fieldMidpoint);
}

function addBitmaskToByte(byte: number, yIsPositive: boolean): number {
  if (!yIsPositive) {
    return (byte |= 1 << 7);
  } else {
    return byte;
  }
}

export { prove, type Proof }