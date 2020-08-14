/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package examples;

import java.math.BigInteger;

import jsnark.util.Util;
import universal.UniversalCircuitGenerator;
import universal.opcodes.opcode1.OperationType;

public class MergeSortSpecifier {

	private int dimension;
	private UniversalCircuitGenerator generator;

	public MergeSortSpecifier(UniversalCircuitGenerator generator, int dimension) {
		this.generator = generator;
		this.dimension = dimension;
	}

	public void setInputToUniversalCircuit() {

		generator.prepareForSpecification();

		BigInteger[] sampleInput = Util.randomBigIntegerArray(dimension, 16);
		int[] array = generator.createStmtArray(sampleInput.length, sampleInput);

		generator.registerMemory("a", dimension);
		generator.registerMemory("b", dimension);

		int[] constantIndices = new int[dimension + 1];
		constantIndices[0] = generator.getZeroIndex();
		constantIndices[1] = generator.getOneIndex();
		for (int i = 2; i < dimension + 1; i++) {
			constantIndices[i] = generator.makeConstant(i);
		}

		for (int i = 0; i < dimension; i++) {
			generator.writeToMemory("a", constantIndices[i], array[i]);
			generator.writeToMemory("b", constantIndices[i], generator.getZeroIndex());
		}

		int left, right, rend;
		int interval;

		int iIdx, jIdx, mIdx;
		int k;

		for (interval = 1; interval < dimension; interval *= 2) {
			for (left = 0; left + interval < dimension; left += interval * 2) {
				right = left + interval;
				rend = right + interval;

				if (rend > dimension)
					rend = dimension;

				mIdx = constantIndices[left];

				iIdx = constantIndices[left];
				jIdx = constantIndices[right];

				for (k = 0; k < 2 * interval; k++) {
					// i < right && j < rend

					int cond1 = generator.isGreaterThan32(constantIndices[right], iIdx);

					int cond2 = generator.isGreaterThan32(constantIndices[rend], jIdx);

					int cond1_cond2 = generator.mulBinaryOp(cond1, cond2);

					int xIdx = generator.readFromMemory("a", iIdx);
					int yIdx = generator.readFromMemory("a", jIdx);
					int smallerIdx;

					int cond_3 = generator.isGreaterThan32(yIdx, xIdx);
					int cond_3_Inv = generator.customBinaryOp(generator.getOneIndex(), cond_3, OperationType.subtract,
							OperationType.add, false);

					int case1 = generator.mulBinaryOp(cond1_cond2, cond_3);
					int case2 = generator.mulBinaryOp(cond1_cond2, cond_3_Inv);

					smallerIdx = generator.muxSelector(xIdx, yIdx, case2);

					iIdx = generator.addBinaryOp(iIdx, case1);
					jIdx = generator.addBinaryOp(jIdx, case2);

					if (k + left < dimension)
						generator.writeToMemory("b", constantIndices[k + left], smallerIdx, cond1_cond2);

					mIdx = generator.addBinaryOp(mIdx, cond1_cond2);

				}

				for (k = left; k < right; k++) {

					int cond1 = generator.isGreaterThan32(constantIndices[right], iIdx);

					int aiIdx = generator.readFromMemory("a", iIdx);
					generator.writeToMemory("b", mIdx, aiIdx, cond1);

					iIdx = generator.addBinaryOp(iIdx, cond1);

					mIdx = generator.addBinaryOp(mIdx, cond1);

				}

				for (k = right; k < rend; k++) {

					int cond1 = generator.isGreaterThan32(constantIndices[rend], jIdx);

					int ajIdx = generator.readFromMemory("a", jIdx);
					generator.writeToMemory("b", mIdx, ajIdx, cond1);

					jIdx = generator.addBinaryOp(jIdx, cond1);
					mIdx = generator.addBinaryOp(mIdx, cond1);

				}

				for (k = left; k < rend; k++) {

					generator.writeToMemory("a", constantIndices[k], generator.readFromMemory("b", constantIndices[k]));
				}

			}
		}

		int[] result = new int[dimension];
		for (int i = 0; i < dimension; i++) {
			result[i] = generator.readFromMemory("a", constantIndices[i]);
		}

		generator.makeStmtOutputArray(result);

		generator.finalizeSpecification();

	}

	public static void main(String[] args) {

		// A small universal circuit for testing
		// In this example, we set the number of operations of the universal circuit
		// such that they are all utilized.
		// This is to measure the amplification cost.
		// See the matrix mul example for a more natural way for defining the universal
		// circuit
		int stmtSize = 20;
		UniversalCircuitGenerator generator = new UniversalCircuitGenerator("univ_circuit", stmtSize, 1041, 81, 6, 30,
				294);
		generator.generateCircuit();

		// now specify the input to the universal circuit
		int dimension = 10;
		MergeSortSpecifier specifier = new MergeSortSpecifier(generator, dimension);
		specifier.setInputToUniversalCircuit();
		generator.getCircuitEvaluator().evaluateCircuit();

	}

}
