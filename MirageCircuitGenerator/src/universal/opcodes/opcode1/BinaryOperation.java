/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package universal.opcodes.opcode1;

import java.math.BigInteger;

import jsnark.circuit.config.Config;
import jsnark.circuit.eval.CircuitEvaluator;
import jsnark.circuit.eval.Instruction;
import jsnark.circuit.operations.Gadget;
import jsnark.circuit.structure.Wire;
import jsnark.util.Util;
import universal.UniversalCircuitEvaluator;
import universal.UniversalCircuitGenerator;
import universal.opcodes.OpEntry;

public class BinaryOperation extends Gadget {

	private int runtimeOperationOrder = -1;
	private OpEntry z1;
	private OpEntry z2;
	private OpEntry z3;
	private Wire prev;

	public static final int c1_INDEX = 0;
	public static final int c2_INDEX = 1;
	public static final int c3_INDEX = 2;
	public static final int c4_INDEX = 3;
	public static final int c5_INDEX = 4;
	public static final int opSelector11_INDEX = 5;
	public static final int opSelector2_INDEX = 6;
	public static final int usePrev_INDEX = 7;
	public static final int cPrevAdd1_INDEX = 8;
	public static final int cPrevAdd2_INDEX = 9;
	public static final int cPrevAdd3_INDEX = 10;
	public static final int opSelector12_INDEX = 11; // TODO: change position

	private Wire c1;
	private Wire c2;
	private Wire c3;
	private Wire c4;
	private Wire c5;
	private Wire opSelector11;
	private Wire opSelector12;
	// If opSelector11 is zero, the first operation will be + if (opSelector12 is
	// zero), or Not equal check if (opSelector12 is 1).
	// If opSelector11 is one , the first operation will be * if (opSelector12 is
	// zero), or equality check if (opSelector12 is 1).

	private Wire opSelector2; // This defines the operation to apply on the result and the previous record in
								// the circuit
	private Wire usePrev;
	private Wire cPrevAdd1;
	private Wire cPrevAdd2;
	private Wire cPrevAdd3;
	private BigInteger[] runtimeSpec;
	private int[] splitInfo;

	public BinaryOperation(OpEntry z1, OpEntry z2, OpEntry z3, Wire prev, BigInteger[] runtimeSpec) {
		this.z1 = z1;
		this.z2 = z2;
		this.z3 = z3;
		this.prev = prev;
		this.runtimeSpec = runtimeSpec;
		buildCircuit();
	}

	public void useRand() {
		runtimeSpec[runtimeSpec.length - 1] = BigInteger.ONE;
	}

	public BinaryOperation(OpEntry z1, OpEntry z2, OpEntry z3, Wire prev) {
		this.z1 = z1;
		this.z2 = z2;
		this.z3 = z3;
		this.prev = prev;
		buildCircuit();
	}

	private void buildCircuit() {
		// TODO Auto-generated method stub
		c1 = generator.createSpecWire();
		c2 = generator.createSpecWire();
		c3 = generator.createSpecWire();
		c4 = generator.createSpecWire();
		c5 = generator.createSpecWire();

		opSelector11 = generator.createSpecWire();
		opSelector2 = generator.createSpecWire();
		usePrev = generator.createSpecWire();
		cPrevAdd1 = generator.createSpecWire();
		cPrevAdd2 = generator.createSpecWire();
		cPrevAdd3 = generator.createSpecWire();
		opSelector12 = generator.createSpecWire();

		generator.specifyProverWitnessComputation(new Instruction() {

			@Override
			public void evaluate(CircuitEvaluator evaluator) {

				UniversalCircuitEvaluator univEvaluator = ((UniversalCircuitEvaluator) evaluator);
				if (runtimeSpec.length != 12) {
					throw new RuntimeException("unexpected runtime spec vector length");
				}

				evaluator.setWireValue(c1, runtimeSpec[0]);
				evaluator.setWireValue(c2, runtimeSpec[1]);
				evaluator.setWireValue(c3, runtimeSpec[2]);
				evaluator.setWireValue(c4, runtimeSpec[3]);
				evaluator.setWireValue(c5, runtimeSpec[4]);
				evaluator.setWireValue(opSelector11, runtimeSpec[5]);
				evaluator.setWireValue(opSelector2, runtimeSpec[6]);
				evaluator.setWireValue(usePrev, runtimeSpec[7]);
				evaluator.setWireValue(cPrevAdd1, runtimeSpec[8]);
				evaluator.setWireValue(cPrevAdd2, runtimeSpec[9]);
				evaluator.setWireValue(cPrevAdd3, runtimeSpec[10]);
				evaluator.setWireValue(opSelector12, runtimeSpec[11]); // TODO: change order of opSelector12

				if (splitInfo != null) {
					univEvaluator.resolveEntry(z3);
					BigInteger z3Value = evaluator.getWireValue(z3.valueWire);

					int sumBitlength = 0;
					for (int i = 0; i < splitInfo.length; i++) {
						sumBitlength += splitInfo[i];
					}
					if (z3Value.bitLength() > sumBitlength) {
						System.out
								.println("z3 value = " + z3Value + ", " + z3Value.bitLength() + " << " + sumBitlength);
						throw new RuntimeException("Cannot Split");
					}
					evaluator.setWireValue(z1.valueWire, z3Value.and(Util.computeMaxValue(splitInfo[0])));
					evaluator.setWireValue(z2.valueWire,
							z3Value.shiftRight(splitInfo[0]).and(Util.computeMaxValue(splitInfo[1])));

					univEvaluator.resolveEntry(z1);
					univEvaluator.resolveEntry(z2);
				} else {

					univEvaluator.resolveEntry(z1);
					univEvaluator.resolveEntry(z2);

					if (evaluator.getWireValue(z3.valueWire) == null) {

						BigInteger v1 = runtimeSpec[0]
								.add(runtimeSpec[1].multiply(evaluator.getWireValue(z1.valueWire)));
						BigInteger v2;
						v2 = runtimeSpec[2].add(runtimeSpec[3].multiply(evaluator.getWireValue(z2.valueWire)));

						BigInteger product1 = v1.multiply(v2).add(runtimeSpec[4]);
						BigInteger sum1 = v1.add(v2).add(runtimeSpec[4]);

						BigInteger result11 = sum1;
						BigInteger result12 = v1.equals(v2) ? BigInteger.ZERO : BigInteger.ONE;
						if (runtimeSpec[5].equals(BigInteger.ONE)) {
							result11 = product1;
							result12 = v1.equals(v2) ? BigInteger.ONE : BigInteger.ZERO;
						}
						BigInteger result1 = result11;
						if (runtimeSpec[11].equals(BigInteger.ONE)) {
							result1 = result12;
						}

						BigInteger sum2 = (result1.add(runtimeSpec[8])
								.add(evaluator.getWireValue(prev).add(runtimeSpec[9]))).add(runtimeSpec[10]);
						BigInteger product2 = (result1.add(runtimeSpec[8])
								.multiply(evaluator.getWireValue(prev).add(runtimeSpec[9]))).add(runtimeSpec[10]);
						BigInteger result2 = sum2;
						if (runtimeSpec[6].equals(BigInteger.ONE)) {
							result2 = product2;
						}

						if (runtimeSpec[7].equals(BigInteger.ONE)) {
							evaluator.setWireValue(z3.valueWire, result2.mod(Config.FIELD_PRIME));
						} else {
							evaluator.setWireValue(z3.valueWire, result1.mod(Config.FIELD_PRIME));
						}
						univEvaluator.resolveEntry(z3);
					}
				}
			}

			public int getOperationCounter() {
				if (runtimeOperationOrder == -1) {
					throw new RuntimeException("unexpected");
				}
				return runtimeOperationOrder;
			}

		});

		Wire c2_z1 = c2.mul(z1.valueWire);
		Wire c4_z2 = c4.mul(z2.valueWire);

		Wire leftSum = c1.add(c2_z1);
		Wire rightSum = c3.add(c4_z2);
		Wire product1 = leftSum.mul(rightSum).add(c5);
		Wire sum1 = leftSum.add(rightSum).add(c5);

		Wire isEqual = c2_z1.isEqualTo(c4_z2);
		Wire isNotEqual = isEqual.invAsBit();

		Wire result11 = sum1.add(opSelector11.mul(product1.sub(sum1)));
		Wire result12 = isNotEqual.add(opSelector11.mul(isEqual.sub(isNotEqual)));
		Wire result1 = result11.add(opSelector12.mul(result12.sub(result11)));

		Wire product2 = result1.add(cPrevAdd1).mul(prev.add(cPrevAdd2)).add(cPrevAdd3);
		Wire sum2 = result1.add(cPrevAdd1).add(prev.add(cPrevAdd2)).add(cPrevAdd3);
		Wire result2 = sum2.add(opSelector2.mul(product2.sub(sum2)));

		generator.addAssertion(usePrev, result2.sub(result1), z3.valueWire.sub(result1), "Binary operation check");
	}

	public void setType(OperationType operationType1, OperationType operationType2, boolean usePrev) {

		BigInteger zero = BigInteger.ZERO;
		BigInteger one = BigInteger.ONE;
		BigInteger negOne = Config.FIELD_PRIME.subtract(BigInteger.ONE);
		BigInteger two = one.add(one);
		BigInteger twoInverse = two.modInverse(Config.FIELD_PRIME);

		BigInteger negTwo = Config.FIELD_PRIME.subtract(two);
		BigInteger negTwoInverse = negTwo.modInverse(Config.FIELD_PRIME);

		BigInteger selector1 = null;
		BigInteger[] constSet1 = null;
		boolean equalOp = false;
		if (operationType1 == OperationType.add) {
			selector1 = zero;
			constSet1 = new BigInteger[] { zero, one, zero, one, zero };
		}
		if (operationType1 == OperationType.mul) {
			selector1 = one;
			constSet1 = new BigInteger[] { zero, one, zero, one, zero };
		}
		if (operationType1 == OperationType.subtract) {
			selector1 = zero;
			constSet1 = new BigInteger[] { zero, one, zero, negOne, zero };
		}
		if (operationType1 == OperationType.xor) {
			selector1 = one;
			constSet1 = new BigInteger[] { one, negTwo, negTwoInverse, one, twoInverse };
		}
		if (operationType1 == OperationType.or) {
			selector1 = one;
			constSet1 = new BigInteger[] { one, negOne, negOne, one, one };
		}
		if (operationType1 == OperationType.isEqual) {
			equalOp = true;
			selector1 = one;
			constSet1 = new BigInteger[] { zero, one, zero, one, zero };
		}
		if (operationType1 == OperationType.isNotEqual) {
			equalOp = true;
			selector1 = zero;
			constSet1 = new BigInteger[] { zero, one, zero, one, zero };
		}

		BigInteger selector2 = zero;
		BigInteger usePrevInput = usePrev ? one : zero;
		BigInteger[] constSet2 = new BigInteger[] { zero, zero, zero };

		if (usePrev) {
			if (operationType2 == OperationType.add) {
				selector2 = zero;
				constSet2 = new BigInteger[] { zero, zero, zero };
			}
			if (operationType2 == OperationType.mul) {
				selector2 = one;
				constSet2 = new BigInteger[] { zero, zero, zero };
			}
			if (operationType2 == OperationType.subtract) {
				selector2 = zero;
				constSet2 = new BigInteger[] { zero, zero, zero };
				for (int i = 2 * selector1.intValue(); i < constSet1.length; i++) {
					constSet1[i] = constSet1[i].multiply(negOne).mod(Config.FIELD_PRIME);
				}
			}
			if (operationType2 == OperationType.xor) {
				selector2 = one;
				constSet2 = new BigInteger[] { one, negTwoInverse, twoInverse };
				for (int i = 2 * selector1.intValue(); i < constSet1.length; i++) {
					constSet1[i] = constSet1[i].multiply(negTwo).mod(Config.FIELD_PRIME);
				}
			}
			if (operationType2 == OperationType.or) {
				selector2 = one;
				constSet2 = new BigInteger[] { one, negOne, one };
				for (int i = 2 * selector1.intValue(); i < constSet1.length; i++) {
					constSet1[i] = constSet1[i].multiply(negOne).mod(Config.FIELD_PRIME);
				}
			}
		}
		register();
		runtimeSpec = new BigInteger[] { constSet1[0], constSet1[1], constSet1[2], constSet1[3], constSet1[4],
				selector1, selector2, usePrevInput, constSet2[0], constSet2[1], constSet2[2],
				equalOp ? BigInteger.ONE : BigInteger.ZERO };

	}

	public void useAsSplit(int[] splitInfo) {
		if (splitInfo.length != 2) {
			throw new IllegalArgumentException();
		}
		this.splitInfo = splitInfo;
		BigInteger zero = BigInteger.ZERO;
		BigInteger one = BigInteger.ONE;

		runtimeSpec = new BigInteger[] { zero, one, zero, one.shiftLeft(splitInfo[0]), zero, zero, zero, zero, zero,
				zero, zero, zero };

		register();

	}

	@Override
	public Wire[] getOutputWires() {
		return null;
	}

	public BigInteger[] getRuntimeSpec() {
		return runtimeSpec;
	}

	public void setRuntimeSpec(BigInteger[] runtimeSpec) {
		this.runtimeSpec = runtimeSpec;
	}

	public Wire getPrev() {
		return prev;
	}

	public Wire getC1() {
		return c1;
	}

	public Wire getC2() {
		return c2;
	}

	public Wire getC3() {
		return c3;
	}

	public Wire getC4() {
		return c4;
	}

	public Wire getC5() {
		return c5;
	}

	public Wire getOpSelector1() {
		return opSelector11;
	}

	public Wire getOpSelector2() {
		return opSelector2;
	}

	public Wire getUsePrev() {
		return usePrev;
	}

	public void multiplyFactor(BigInteger factor, int[] indices) {
		if (runtimeSpec == null) {
			throw new NullPointerException("Call set type first");
		}
		for (int i : indices) {
			runtimeSpec[i] = runtimeSpec[i].multiply(factor);
		}
	}

	public int[] getSplitInfo() {
		return splitInfo;
	}

	public void setSplitInfo(int[] splitInfo) {
		this.splitInfo = splitInfo;
	}

	public void register() {
		runtimeOperationOrder = UniversalCircuitGenerator.globalRuntimeCounter++;
	}

	public int getOperationOrder() {
		return runtimeOperationOrder;
	}
}
