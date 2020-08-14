/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package universal.opcodes.opcode3;

import java.math.BigInteger;
import java.util.Arrays;

import jsnark.circuit.eval.CircuitEvaluator;
import jsnark.circuit.eval.Instruction;
import jsnark.circuit.operations.Gadget;
import jsnark.circuit.structure.CircuitGenerator;
import jsnark.circuit.structure.Wire;
import universal.UniversalCircuitEvaluator;
import universal.UniversalCircuitGenerator;
import universal.opcodes.OpEntry;

public class Split32Operation extends Gadget {

	public static final int NUM_ENTRIES = 32 + 2 + 4;
	private int runtimeOperationOrder = -1;

	private OpEntry[] elements;
	private OpEntry z1;
	private OpEntry z2;
	private OpEntry[] zBytes;

	private Wire enableBinarychecks;
	private Wire[] coefficientSet1;
	private Wire[] coefficientSet2;

	private BigInteger[][] runtimeSpec;

	public Split32Operation(OpEntry[] bitWires, OpEntry z1, OpEntry z2, OpEntry[] zBytes, BigInteger[][] runtimeSpec) {
		this.elements = bitWires;
		this.z1 = z1;
		this.z2 = z2;
		this.zBytes = zBytes;
		this.runtimeSpec = runtimeSpec;
		buildCircuit();
	}

	private void buildCircuit() {

//		counter = serialCounter++;
		coefficientSet1 = generator.createSpecWireArray(32);
		coefficientSet2 = generator.createSpecWireArray(32);
		enableBinarychecks = generator.createSpecWire();

		generator.specifyProverWitnessComputation(new Instruction() {

			@Override
			public void evaluate(CircuitEvaluator evaluator) {

				UniversalCircuitEvaluator univEvaluator = (UniversalCircuitEvaluator) evaluator;
				univEvaluator.setWireValue(enableBinarychecks, runtimeSpec[0][0]);
				for (int i = 0; i < 32; i++) {
					univEvaluator.setWireValue(coefficientSet1[i], runtimeSpec[1][i]);
					univEvaluator.setWireValue(coefficientSet2[i], runtimeSpec[2][i]);
				}

				univEvaluator.resolveEntry(z1);
				univEvaluator.resolveEntry(z2);
				for (int i = 0; i < elements.length; i++) {
					univEvaluator.resolveEntry(elements[i]);
				}
				for (int i = 0; i < zBytes.length; i++) {
					univEvaluator.resolveEntry(zBytes[i]);
				}

				boolean bitsDefined = true;
				for (int i = 0; i < elements.length; i++) {
					if (univEvaluator.getWireValue(elements[i].valueWire) == null)
						bitsDefined = false;
				}

				boolean z1Defined = univEvaluator.getWireValue(z1.valueWire) != null;

				boolean zBytesDefined = true;

				for (int i = 0; i < zBytes.length; i++) {
					if (univEvaluator.getWireValue(zBytes[i].valueWire) == null)
						zBytesDefined = false;
				}

				if (!z1Defined) {
					if (!zBytesDefined) {
						BigInteger sum1 = BigInteger.ZERO;
						BigInteger sum2 = BigInteger.ZERO;
						BigInteger byteSum = BigInteger.ZERO;
						for (int i = 0; i < 32; i++) {
							sum1 = sum1
									.add(runtimeSpec[1][i].multiply(univEvaluator.getWireValue(elements[i].valueWire)));
							byteSum = byteSum.add(univEvaluator.getWireValue(elements[i].valueWire)
									.multiply(BigInteger.ONE.shiftLeft(i % 8)));
							if ((i + 1) % 8 == 0) {
								univEvaluator.setWireValue(zBytes[i / 8].valueWire, byteSum);
								byteSum = BigInteger.ZERO;
							}
							sum2 = sum2.add(runtimeSpec[2][i].multiply(evaluator.getWireValue(elements[i].valueWire)));
						}
						univEvaluator.setWireValue(z1.valueWire, sum1);
						univEvaluator.setWireValue(z2.valueWire, sum2);

					} else {

						for (int i = 0; i < 32; i++) {
							if (univEvaluator.getWireValue(elements[i].valueWire) == null) {
								univEvaluator.setWireValue(elements[i].valueWire,
										univEvaluator.getWireValue(zBytes[i / 8].valueWire).testBit(i % 8)
												? BigInteger.ONE
												: BigInteger.ZERO);
							}
						}

						for (int i = 0; i < elements.length; i++) {
							univEvaluator.resolveEntry(elements[i]);
						}

						BigInteger sum1 = BigInteger.ZERO;
						BigInteger sum2 = BigInteger.ZERO;
						for (int i = 0; i < 32; i++) {
							sum1 = sum1
									.add(runtimeSpec[1][i].multiply(univEvaluator.getWireValue(elements[i].valueWire)));
							sum2 = sum2
									.add(runtimeSpec[2][i].multiply(univEvaluator.getWireValue(elements[i].valueWire)));
						}
						univEvaluator.setWireValue(z1.valueWire, sum1);
						univEvaluator.setWireValue(z2.valueWire, sum2);

					}
				} else {
					if (!bitsDefined) {
						for (int i = 0; i < 32; i++) {
							if (univEvaluator.getWireValue(elements[i].valueWire) == null) {
								univEvaluator.setWireValue(elements[i].valueWire,
										univEvaluator.getWireValue(z1.valueWire).testBit(i) ? BigInteger.ONE
												: BigInteger.ZERO);
							}
						}

						BigInteger byteSum = BigInteger.ZERO;
						for (int i = 0; i < 32; i++) {
							byteSum = byteSum.add(univEvaluator.getWireValue(elements[i].valueWire)
									.multiply(BigInteger.ONE.shiftLeft(i % 8)));
							if ((i + 1) % 8 == 0) {
								univEvaluator.setWireValue(zBytes[i / 8].valueWire, byteSum);
								byteSum = BigInteger.ZERO;
							}
						}

						BigInteger sum2 = BigInteger.ZERO;
						for (int i = 0; i < 32; i++) {
							sum2 = sum2
									.add(runtimeSpec[2][i].multiply(univEvaluator.getWireValue(elements[i].valueWire)));
						}
						univEvaluator.setWireValue(z2.valueWire, sum2);
					} else {
						BigInteger byteSum = BigInteger.ZERO;
						for (int i = 0; i < 32; i++) {
							byteSum = byteSum.add(univEvaluator.getWireValue(elements[i].valueWire)
									.multiply(BigInteger.ONE.shiftLeft(i % 8)));
							if ((i + 1) % 8 == 0) {
								univEvaluator.setWireValue(zBytes[i / 8].valueWire, byteSum);
								byteSum = BigInteger.ZERO;
							}
						}

						BigInteger sum2 = BigInteger.ZERO;
						for (int i = 0; i < 32; i++) {
							sum2 = sum2
									.add(runtimeSpec[2][i].multiply(univEvaluator.getWireValue(elements[i].valueWire)));
						}
						univEvaluator.setWireValue(z2.valueWire, sum2);
					}
				}
				univEvaluator.resolveEntry(z1);
				univEvaluator.resolveEntry(z2);
				for (int i = 0; i < elements.length; i++) {
					univEvaluator.resolveEntry(elements[i]);
				}
				for (int i = 0; i < zBytes.length; i++) {
					univEvaluator.resolveEntry(zBytes[i]);
				}
			}

			public int getOperationCounter() {
				if (runtimeOperationOrder == -1) {
					throw new RuntimeException("unexpected");
				}
				return runtimeOperationOrder;
			}
		});

		for (OpEntry w : elements) {
			generator.addBinaryAssertion(w.valueWire.mul(enableBinarychecks), "binary assertion");
		}

		Wire zeroWire = CircuitGenerator.getActiveCircuitGenerator().getZeroWire();
		Wire sum1 = zeroWire;
		Wire sumBytes = zeroWire;
		Wire sum2 = zeroWire;
		for (int i = 0; i < elements.length; i++) {
			sum1 = sum1.add(elements[i].valueWire.mul(coefficientSet1[i]));
			sumBytes = sumBytes.add(elements[i].valueWire.mul(2, i % 8));
			if ((i + 1) % 8 == 0) {
				generator.addEqualityAssertion(sumBytes, zBytes[i / 8].valueWire, "Assertion in Split32 (Bytes)");
				sumBytes = zeroWire;
			}
			sum2 = sum2.add(elements[i].valueWire.mul(coefficientSet2[i]));
		}
		generator.addEqualityAssertion(sum1, z1.valueWire, "assertion 1 in Split32");
		generator.addEqualityAssertion(sum2, z2.valueWire, "assertion 2 in Split32");
	}

	public void setOperation(boolean split, BigInteger[] set1, BigInteger[] set2) {

		if (set1 == null) {
			set1 = new BigInteger[32];
			Arrays.fill(set1, BigInteger.ZERO);
		}
		if (set2 == null) {
			set2 = new BigInteger[32];
			Arrays.fill(set2, BigInteger.ZERO);
		}
		runtimeSpec = new BigInteger[][] { new BigInteger[] { split ? BigInteger.ONE : BigInteger.ZERO }, set1, set2 };
		register();

	}

	@Override
	public Wire[] getOutputWires() {
		return null;
	}

	public BigInteger[][] getRuntimeSpec() {
		return runtimeSpec;
	}

	public void setRuntimeSpec(BigInteger[][] runtimeSpec) {
		this.runtimeSpec = runtimeSpec;
	}

//	public static int getSerialCounter() {
//		return serialCounter;
//	}

//	public int getCounter() {
//		return counter;
//	}

	public void register() {
		runtimeOperationOrder = UniversalCircuitGenerator.globalRuntimeCounter++;
	}

	public int getOperationOrder() {
		return runtimeOperationOrder;
	}

}
