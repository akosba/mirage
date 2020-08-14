/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package examples;

import java.math.BigInteger;

import jsnark.util.Util;
import universal.UniversalCircuitGenerator;
import universal.opcodes.opcode1.OperationType;

public class MatMulSpecifier {

	private int dimension;
	private UniversalCircuitGenerator generator;

	public MatMulSpecifier(UniversalCircuitGenerator generator, int dimension) {
		this.generator = generator;
		this.dimension = dimension;
	}

	public void setInputToUniversalCircuit() {

		generator.prepareForSpecification();

		BigInteger[] sampleInput1 = Util.randomBigIntegerArray(dimension * dimension, 32);
		BigInteger[] sampleInput2 = Util.randomBigIntegerArray(dimension * dimension, 32);

		int[] m1 = generator.createStmtArray(sampleInput1.length, sampleInput1);
		int[] m2 = generator.createStmtArray(sampleInput2.length, sampleInput2);

		int[][] M1 = new int[dimension][dimension];
		int[][] M2 = new int[dimension][dimension];
		
		for (int i = 0; i < dimension; i++) {
			for (int j = 0; j < dimension; j++) {
				M1[i][j] = m1[i * dimension + j];
				M2[i][j] = m2[i * dimension + j];
			}
		}

		int[][] results = new int[dimension][dimension];

		for (int i = 0; i < dimension; i++) {
			for (int j = 0; j < dimension; j++) {
				generator.mulBinaryOp(M1[i][0], M2[0][j]);
				for (int k = 1; k < dimension; k++) {
					results[i][j] = generator.customBinaryOp(M1[i][k], M2[k][j], OperationType.mul, OperationType.add,
							true);
				}
			}
		}

		// if we need to compute the result mod 2^32
//		for(int i = 0; i < dimension; i++){
//			for(int j = 0; j < dimension; j++){
//				int[] splitted = generator.splitBinary(results[i][j], new int[]{32, 32*3});
//				generator.addElementToVerify32(splitted[0]);
//				generator.forceBitwidth(splitted[1], 3*32);
//				results[i][j] = splitted[0];
//			}			
//		}

		for (int i = 0; i < dimension; i++)
			generator.makeStmtOutputArray(results[i]);

		generator.finalizeSpecification();
	}

	public static void main(String[] args) {

		// A small universal circuit for testing	
		int stmtSize = 50;
		int budget = 10000; // max number of constraints for all operations
		UniversalCircuitGenerator generator = new UniversalCircuitGenerator("univ_circuit", stmtSize, budget);
		generator.generateCircuit();
		generator.writeCircuitFile();
		
		// now specify the input to the universal circuit
		int dimension = 3;
		MatMulSpecifier specifier = new MatMulSpecifier(generator, dimension);
		specifier.setInputToUniversalCircuit();
		generator.getCircuitEvaluator().evaluateCircuit();
		generator.getCircuitEvaluator().writeInputFile("matmul");
	}
}
