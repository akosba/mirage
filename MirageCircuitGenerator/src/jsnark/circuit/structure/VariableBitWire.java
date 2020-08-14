/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package jsnark.circuit.structure;

public class VariableBitWire extends BitWire {

	public VariableBitWire(int wireId) {
		super(wireId);
	}

	public WireArray getBitWires() {
		return new WireArray(new Wire[] { this });
	}

}
