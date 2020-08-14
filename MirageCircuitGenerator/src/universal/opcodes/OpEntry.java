/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package universal.opcodes;

import java.math.BigInteger;

import jsnark.circuit.eval.CircuitEvaluator;
import jsnark.circuit.structure.CircuitGenerator;
import jsnark.circuit.structure.Wire;
import universal.UniversalCircuitGenerator;

public class OpEntry implements Comparable<OpEntry>{
	
	public Wire indexWire;
	public Wire valueWire;

	public OpEntry(boolean isStmt) {
		indexWire = CircuitGenerator.getActiveCircuitGenerator()
				.createSpecWire();
		if (isStmt) {
			valueWire = CircuitGenerator.getActiveCircuitGenerator()
					.createStmtWire();
		} else {
			valueWire = CircuitGenerator.getActiveCircuitGenerator()
					.createProverWitnessWire();
		}
	}

	public OpEntry(Wire w1, Wire w2) {
		indexWire = w1;
		valueWire = w2;
	}

	@Override
	public int compareTo(OpEntry o) {
		CircuitEvaluator e = ((UniversalCircuitGenerator)CircuitGenerator.getActiveCircuitGenerator()).getCircuitEvaluator();
		BigInteger i1 = e.getWireValue(indexWire);
		BigInteger i2  = e.getWireValue(o.indexWire);
//		System.out.println(i1 + "__" + i2);
		return i1.compareTo(i2);
	}

}