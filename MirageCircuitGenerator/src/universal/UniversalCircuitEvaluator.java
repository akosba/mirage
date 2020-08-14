/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package universal;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;

import jsnark.circuit.config.Config;
import jsnark.circuit.eval.CircuitEvaluator;
import jsnark.circuit.eval.Instruction;
import jsnark.circuit.operations.WireLabelInstruction;
import jsnark.circuit.operations.WireLabelInstruction.LabelType;
import jsnark.circuit.structure.CircuitGenerator;

public class UniversalCircuitEvaluator extends CircuitEvaluator{

	private HashMap<BigInteger, BigInteger> universalAssignment;

	public UniversalCircuitEvaluator(CircuitGenerator circuitGenerator) {
		super(circuitGenerator);
		universalAssignment = new HashMap<>();
	}
	
	public BigInteger getValueOfIndex(int index){
		return universalAssignment.get(BigInteger.valueOf(index));
	}
	
	public BigInteger[] getValuesOfIndices(int[] indices){
		BigInteger[] values = new BigInteger[indices.length];
		for(int i = 0; i < indices.length; i++){
			values[i] = universalAssignment.get(BigInteger.valueOf(indices[i]));
		}
		return values;
	}
	
	public void resolveEntry(universal.opcodes.OpEntry entry){
		if(getWireValue(entry.indexWire)!=null){
			if(getWireValue(entry.valueWire)==null){
				setWireValue(entry.valueWire, universalAssignment.get(getWireValue(entry.indexWire)));
			} else{
				setUniversalAssignment(getWireValue(entry.indexWire), getWireValue(entry.valueWire));
			}
		} 
	}
	
	public void setUniversalAssignment(BigInteger key, BigInteger value){
		if(value == null)
			return;
		value = value.mod(Config.FIELD_PRIME);
		if(universalAssignment.get(key)!=null)
			if(!value.equals(universalAssignment.get(key))){
				System.out.println(key + ", " + value + "," + universalAssignment.get(key));
				throw new RuntimeException("Mismatch");
			}
		universalAssignment.put(key, value);
	}

	
	public void writeInputFile(String appName) {
		try {
			LinkedHashMap<Instruction, Instruction> evalSequence = circuitGenerator
					.getEvaluationQueue();

			PrintWriter printWriter = new PrintWriter(
					 appName + ".in");
			for (Instruction e : evalSequence.keySet()) {
				if (e instanceof WireLabelInstruction
						&& (((WireLabelInstruction) e).getType() == LabelType.spec
								|| ((WireLabelInstruction) e).getType() == LabelType.witness
								|| ((WireLabelInstruction) e).getType() == LabelType.rnd || ((WireLabelInstruction) e)
								.getType() == LabelType.stmt)) {
					int id = ((WireLabelInstruction) e).getWire().getWireId();
					printWriter.println(id + " "
							+ wireValueAssignment[id].toString(16));
				}
			}
			printWriter.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void evaluateCircuit() {

		// Different evaluator logic from jsnark
		
		System.out.println("Running Circuit Evaluator for < " + circuitGenerator.getName() + " >");

		LinkedHashMap<Instruction, Instruction> evalSequence = circuitGenerator.getEvaluationQueue();
		ArrayList<Instruction> list = new ArrayList<>();
		for (Instruction e : evalSequence.keySet()) {
			list.add(e);
		}

		Collections.sort(list, new Comparator<Instruction>() {
			@Override
			public int compare(Instruction arg0, Instruction arg1) {
				return arg0.getOperationCounter() - arg1.getOperationCounter();
			}
		});

		for (Instruction e : list) {
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
