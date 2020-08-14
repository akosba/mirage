/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package examples;

import java.math.BigInteger;
import java.util.ArrayList;

import examples.auxiliary.Auction;
import examples.auxiliary.SHA256;
import jsnark.util.Util;
import universal.UniversalCircuitGenerator;
import universal.opcodes.opcode2.BitwiseOperationType;

public class HawkManagerAuctionSpecifier {

	private int numParicipants;
	private UniversalCircuitGenerator generator;

	public HawkManagerAuctionSpecifier(UniversalCircuitGenerator generator, int numParicipants) {
		this.generator = generator;
		this.numParicipants = numParicipants;
	}

	public void setInputToUniversalCircuit() {

		generator.prepareForSpecification();

		int[][] secretInputRandomness = generator.makeWitness2DArray(numParicipants, 4 * 2);
		int[][] secretInputs = generator.makeWitness2DArray(numParicipants, 3 * 2);
		int[][] secretSymKeys = generator.makeWitness2DArray(numParicipants, 8 * 2);
		int[][] secretOutputRandomness = generator.makeWitness2DArray(numParicipants, 4 * 2);

		for (int x : generator.getWitnessIndices()) {
			generator.getCircuitEvaluator().setUniversalAssignment(BigInteger.valueOf(x),
					Util.nextRandomBigInteger(32));
		}

		int[][] secretInputValues = generator.makeWitness2DArray(numParicipants, 2);
		for (int i = 1; i < numParicipants; i++) {
			generator.getCircuitEvaluator().setUniversalAssignment(BigInteger.valueOf(secretInputValues[i][0]),
					Util.nextRandomBigInteger(32));
			generator.getCircuitEvaluator().setUniversalAssignment(BigInteger.valueOf(secretInputValues[i][1]),
					Util.nextRandomBigInteger(10));
		}
		generator.getCircuitEvaluator().setUniversalAssignment(BigInteger.valueOf(secretInputValues[0][0]),
				BigInteger.ZERO);
		generator.getCircuitEvaluator().setUniversalAssignment(BigInteger.valueOf(secretInputValues[0][1]),
				BigInteger.ZERO);

		ArrayList<Integer> outputs = new ArrayList<>();

		int[] auctionInputValues = new int[numParicipants];
		for (int i = 0; i < numParicipants; i++) {
			auctionInputValues[i] = generator.addBinaryOp(secretInputValues[i][0], secretInputValues[i][1]);
			generator.setRuntimeSpecEntryForBinaryOp(3, BigInteger.ONE.shiftLeft(32));
		}
		int[] auctionOutputValues = new Auction(generator, auctionInputValues).getOutputs();

		int[][] secretOutputValues = new int[numParicipants][];
		for (int i = 0; i < numParicipants; i++) {
			secretOutputValues[i] = generator.splitBinary(auctionOutputValues[i], new int[] { 32, 32 });
		}
		// in commitments

		for (int i = 0; i < numParicipants; i++) {
			int[] hashInput = Util.concat(secretInputValues[i], secretInputs[i]);
			hashInput = Util.concat(hashInput, secretInputRandomness[i]);
			hashInput = Util.concat(hashInput, secretSymKeys[i]);
			int[] digest = new SHA256(generator, hashInput).getOutputs();

			for (int d : digest) {
				outputs.add(d);
			}
		}

		int zeroIndex = generator.getZeroIndex();
		// out commitments
		for (int i = 0; i < numParicipants; i++) {
			int[] hashInput = Util.concat(secretOutputValues[i],
					new int[] { zeroIndex, zeroIndex, zeroIndex, zeroIndex, zeroIndex, zeroIndex });
			hashInput = Util.concat(hashInput, secretOutputRandomness[i]);
			int[] digest = new SHA256(generator, hashInput).getOutputs();

			for (int d : digest) {
				outputs.add(d);
			}
		}

		// encrypt
		for (int i = 0; i < numParicipants; i++) {
			for (int j = 0; j < 2; j++) {
				outputs.add(
						generator.bitwiseOp(secretOutputValues[i][j], secretSymKeys[i][j], BitwiseOperationType.xor));
			}
			for (int j = 2; j < 8; j++) {
				outputs.add(secretSymKeys[i][j]);
			}
			for (int j = 8; j < 16; j++) {
				outputs.add(generator.bitwiseOp(secretOutputRandomness[i][j - 8], secretSymKeys[i][j],
						BitwiseOperationType.xor));
			}
		}

		for (int i = 0; i < outputs.size(); i += 2) {
			generator.makeStmtOutput(generator.addBinaryOp(outputs.get(i), outputs.get(i + 1)));
			generator.setRuntimeSpecEntryForBinaryOp(3, BigInteger.ONE.shiftLeft(32));
		}
		generator.finalizeSpecification();
	}

	public static void main(String[] args) {


		int stmtSize = 300;
		int budget = 11000000; // max number of constraints for all operations
		// This is a large circuit that would need large memory
		UniversalCircuitGenerator generator = new UniversalCircuitGenerator("UnivCircuit", stmtSize, budget);
		generator.generateCircuit();
		generator.writeCircuitFile();
		
		// now specify the input to the universal circuit
		int numParticipants = 6;
		HawkManagerAuctionSpecifier specifier = new HawkManagerAuctionSpecifier(generator, numParticipants);
		specifier.setInputToUniversalCircuit();
		generator.getCircuitEvaluator().evaluateCircuit();
	}

}
