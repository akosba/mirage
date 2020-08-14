/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/


package examples.auxiliary;

import universal.UniversalCircuitGenerator;
import universal.opcodes.opcode1.OperationType;

public class Auction {

	private int[] inputs;
	private int[] outputs;
	private UniversalCircuitGenerator generator;

	public Auction(UniversalCircuitGenerator generator, int[] inputs) {
		this.generator = generator;
		this.inputs = inputs;
		specifyCircuit();
	}

	private void specifyCircuit() {

		int numParticipants = inputs.length - 1;
		int winnerIndex = generator.getOneIndex();
		int currentMax = inputs[1];
		int[] indices = new int[numParticipants + 1]; // constants unnecessary, but to simplify code for now
		indices[0] = generator.getZeroIndex();
		indices[1] = generator.getOneIndex();
		for (int i = 2; i < numParticipants + 1; i++) {
			indices[i] = generator.makeConstant( i);
		}

		for (int i = 2; i < numParticipants + 1; i++) {
			int greaterThan = generator.isGreaterThan64( inputs[i], currentMax);
			currentMax = generator.muxSelector( currentMax, inputs[i], greaterThan);
			winnerIndex = generator.muxSelector( winnerIndex, indices[i], greaterThan);
		}
		outputs = new int[inputs.length];
		outputs[0] = generator.addBinaryOp( inputs[0], currentMax);
		for (int i = 1; i < numParticipants + 1; i++) {
			int isWinner = generator.isEqual( winnerIndex, indices[i]);
			int newBalance = generator.customBinaryOp( inputs[i], currentMax, OperationType.subtract,
					OperationType.add, false);
			outputs[i] = generator.muxSelector( inputs[i], newBalance, isWinner);
		}
	}

	public int[] getInputs() {
		return inputs;
	}

	public int[] getOutputs() {
		return outputs;
	}

}
