/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package examples;

import java.math.BigInteger;
import java.util.Arrays;

import examples.auxiliary.AES128;
import universal.UniversalCircuitGenerator;

public class AES128Specifier {
	
	private UniversalCircuitGenerator generator;
	
	// sample input
	private BigInteger keyV = new BigInteger("2b7e151628aed2a6abf7158809cf4f3c", 16);
	private BigInteger msgV = new BigInteger("ae2d8a571e03ac9c9eb76fac45af8e51", 16);
	
	// expected output:0xf5d3d58503b9699de785895a96fdbaaf

	public AES128Specifier(UniversalCircuitGenerator generator) {
		this.generator = generator;
	}
	
	
	public void setInputToUniversalCircuit() {
		
		generator.prepareForSpecification();
		byte[] keyArray = keyV.toByteArray();
		byte[] msgArray = msgV.toByteArray();
		msgArray = Arrays.copyOfRange(msgArray, msgArray.length - 16,
				msgArray.length);
		keyArray = Arrays.copyOfRange(keyArray, keyArray.length - 16,
				keyArray.length);

		
		BigInteger[] sampleInput = new BigInteger[16]; 
		BigInteger[] sampleKey = new BigInteger[16]; 
		
		
		for (int i = 0; i < msgArray.length; i++) {
			sampleInput[i]=BigInteger.valueOf(msgArray[i] & 0xff);
		}

		for (int i = 0; i < keyArray.length; i++) {
			sampleKey[i]=BigInteger.valueOf(keyArray[i] & 0xff);
		}

		int[] circuitInput = generator.createStmtArray( 16, sampleInput);
		int[] key = generator.createStmtArray( 16, sampleKey);
		int[] outputs = new AES128(generator, circuitInput, key).getOutputs();
		
		generator.makeStmtOutputArray(outputs);
		generator.finalizeSpecification();
	}
	
	
	public static void main(String[] args) {

		// In this example, we set the number of operations of the universal circuit such that they are all utilized.
		// This is to measure the amplification cost.
		// See the matrix mul example for a more natural way for defining the universal circuit
		
		UniversalCircuitGenerator generator =  new UniversalCircuitGenerator("UnivCircuit_AES", 48, 1243, 742, 180, 257, 456);
		generator.generateCircuit();
		
		AES128Specifier specifier = new AES128Specifier(generator);
		specifier.setInputToUniversalCircuit();
		generator.getCircuitEvaluator().evaluateCircuit();
		
//		generator.prepFiles();
	}

}
