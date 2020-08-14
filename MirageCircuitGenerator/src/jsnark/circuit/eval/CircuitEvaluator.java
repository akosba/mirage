/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package jsnark.circuit.eval;

import java.math.BigInteger;
import java.util.LinkedHashMap;

import jsnark.circuit.config.Config;
import jsnark.circuit.structure.CircuitGenerator;
import jsnark.circuit.structure.Wire;
import jsnark.circuit.structure.WireArray;

public class CircuitEvaluator {

	protected CircuitGenerator circuitGenerator;
	protected BigInteger[] wireValueAssignment;

	public CircuitEvaluator(CircuitGenerator circuitGenerator) {
		this.circuitGenerator = circuitGenerator;
		wireValueAssignment = new BigInteger[circuitGenerator.getNumWires()];
		wireValueAssignment[circuitGenerator.getOneWire().getWireId()] = BigInteger.ONE;
	}

	public void setWireValue(Wire w, BigInteger v) {
		
		if (v == null)
			return;
		v = v.mod(Config.FIELD_PRIME);
		if (wireValueAssignment[w.getWireId()] != null) {
			if (!v.equals(wireValueAssignment[w.getWireId()])) {
				System.out.println(w.getWireId() + ", " + v + ",," + wireValueAssignment[w.getWireId()]);
				throw new NullPointerException();
			}
		} else {
			wireValueAssignment[w.getWireId()] = v;
		}
	}

	public BigInteger getWireValue(Wire w) {
		BigInteger v = wireValueAssignment[w.getWireId()];
		if (v == null) {
			WireArray bits = w.getBitWiresIfExistAlready();
			if (bits != null) {
				BigInteger sum = BigInteger.ZERO;
				for (int i = 0; i < bits.size(); i++) {
					sum = sum.add(wireValueAssignment[bits.get(i).getWireId()].shiftLeft(i));
				}
				v = sum;
			}
		}
		return v;
	}

	public BigInteger[] getWiresValues(Wire[] w) {
		BigInteger[] values = new BigInteger[w.length];
		for (int i = 0; i < w.length; i++) {
			values[i] = getWireValue(w[i]);
		}
		return values;
	}

	public void setWireValue(Wire wire, long v) {
		setWireValue(wire, new BigInteger(v + ""));
	}

	public void setWireValue(Wire[] wires, BigInteger[] v) {
		for (int i = 0; i < v.length; i++) {
			setWireValue(wires[i], v[i]);
		}
		for (int i = v.length; i < wires.length; i++) {
			setWireValue(wires[i], BigInteger.ZERO);
		}
	}

	public BigInteger[] getAssignment() {
		return wireValueAssignment;
	}
	
	public void evaluate() {
		
		System.out.println("Running Circuit Evaluator for < " + circuitGenerator.getName() + " >");
		LinkedHashMap<Instruction, Instruction> evalSequence = circuitGenerator.getEvaluationQueue();

		for (Instruction e : evalSequence.keySet()) {
			e.evaluate(this);

			e.emit(this);
		}
		// check that each wire has been assigned a value
		for (int i = 0; i < wireValueAssignment.length; i++) {
			if (wireValueAssignment[i] == null) {
				throw new RuntimeException("Wire#" + i + "is without value");
			}
		}
		System.out.println("Circuit Evaluation Done for < " + circuitGenerator.getName() + " >\n\n");

	}

}
