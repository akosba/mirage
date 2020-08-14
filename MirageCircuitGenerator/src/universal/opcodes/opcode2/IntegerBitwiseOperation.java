/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package universal.opcodes.opcode2;

import java.math.BigInteger;
import java.util.Arrays;

import jsnark.circuit.config.Config;
import jsnark.circuit.eval.CircuitEvaluator;
import jsnark.circuit.eval.Instruction;
import jsnark.circuit.operations.Gadget;
import jsnark.circuit.structure.CircuitGenerator;
import jsnark.circuit.structure.Wire;
import jsnark.circuit.structure.WireArray;
import jsnark.util.Util;
import universal.UniversalCircuitEvaluator;
import universal.UniversalCircuitGenerator;
import universal.opcodes.OpEntry;
import universal.opcodes.opcode1.OperationType;

public class IntegerBitwiseOperation extends Gadget {

	public static final int BITWIDTH = 32;
	private int runtimeOperationOrder = -1;

	private OpEntry z1;
	private OpEntry z2;
	private OpEntry z3;

	// order: [AND, XOR, OR] - [invFirst only] AND, XOR, OR, [InvSecond Only] AND, XOR, OR, [Inv Both] AND, XOR, OR]
	private Wire[] selectors; 
	
	// This operation can also work as a simplified opcode 1 if desired. The specifiers are included here as well.
	private Wire c1;
	private Wire c2;
	private Wire c3;
	private Wire c4;
	private Wire c5;
	private Wire opSelector;

	private BigInteger[] runtimeSpec; // c1, c2, c3, c4, c5, opSelector, 12 selectors
	private int[] splitInfo;

	public IntegerBitwiseOperation(OpEntry z1, OpEntry z2, OpEntry z3, BigInteger[] runtimeSpec) {
		this.z1 = z1;
		this.z2 = z2;
		this.z3 = z3;
		this.runtimeSpec = runtimeSpec;
		buildCircuit();
	}

	private void buildCircuit() {

		selectors = generator.createSpecWireArray(12);
		c1 = generator.createSpecWire();
		c2 = generator.createSpecWire();
		c3 = generator.createSpecWire();
		c4 = generator.createSpecWire();
		c5 = generator.createSpecWire();
		opSelector = generator.createSpecWire();

		generator.specifyProverWitnessComputation(new Instruction() {

			@Override
			public void evaluate(CircuitEvaluator evaluator) {

				UniversalCircuitEvaluator univEvaluator = ((UniversalCircuitEvaluator) evaluator);
				if (runtimeSpec.length != 6 + 12) {
					throw new RuntimeException("unexpected runtime spec length");
				}

				evaluator.setWireValue(c1, runtimeSpec[0]);
				evaluator.setWireValue(c2, runtimeSpec[1]);
				evaluator.setWireValue(c3, runtimeSpec[2]);
				evaluator.setWireValue(c4, runtimeSpec[3]);
				evaluator.setWireValue(c5, runtimeSpec[4]);
				evaluator.setWireValue(opSelector, runtimeSpec[5]);

				for (int i = 0; i < 12; i++) {
					evaluator.setWireValue(selectors[i], runtimeSpec[6 + i]);

				}

				if (splitInfo != null) {
					univEvaluator.resolveEntry(z3);
					BigInteger z3Value = evaluator.getWireValue(z3.valueWire);
					int sumBitlength = 0;
					for (int i = 0; i < splitInfo.length; i++) {
						sumBitlength += splitInfo[i];
					}
					if (z3Value.bitLength() > sumBitlength) {
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

						boolean bitwiseOp = false;

						BigInteger z1Val = evaluator.getWireValue(z1.valueWire);
						BigInteger z2Val = evaluator.getWireValue(z2.valueWire);

						int shift = 6;
						for (int i = 0; i < 12; i++) {
							if (runtimeSpec[shift + i].equals(BigInteger.ONE)) {
								bitwiseOp = true;
							}
						}

						BigInteger result1 = BigInteger.ZERO;
						BigInteger andResult = z1Val.and(z2Val).multiply(runtimeSpec[shift + 0]);
						result1 = result1.add(andResult);
						BigInteger xorResult = z1Val.xor(z2Val).multiply(runtimeSpec[shift + 1]);

						result1 = result1.add(xorResult);

						BigInteger orResult = z1Val.or(z2Val).multiply(runtimeSpec[shift + 2]);
						result1 = result1.add(orResult);

						BigInteger andResultInv1 = invBits(z1Val).and(z2Val).multiply(runtimeSpec[shift + 3]);
						result1 = result1.add(andResultInv1);
						BigInteger xorResultInv1 = invBits(z1Val).xor(z2Val).multiply(runtimeSpec[shift + 4]);
						result1 = result1.add(xorResultInv1);
						BigInteger orResultInv1 = invBits(z1Val).or(z2Val).multiply(runtimeSpec[shift + 5]);
						result1 = result1.add(orResultInv1);

						BigInteger andResultInv2 = invBits(z2Val).and(z1Val).multiply(runtimeSpec[shift + 6]);
						result1 = result1.add(andResultInv2);
						BigInteger xorResultInv2 = invBits(z2Val).xor(z1Val).multiply(runtimeSpec[shift + 7]);
						result1 = result1.add(xorResultInv2);
						BigInteger orResultInv2 = invBits(z2Val).or(z1Val).multiply(runtimeSpec[shift + 8]);
						result1 = result1.add(orResultInv2);

						BigInteger andResultInv12 = invBits(z2Val).and(invBits(z1Val)).multiply(runtimeSpec[shift + 9]);
						result1 = result1.add(andResultInv12);
						BigInteger xorResultInv12 = invBits(z2Val).xor(invBits(z1Val))
								.multiply(runtimeSpec[shift + 10]);
						result1 = result1.add(xorResultInv12);
						BigInteger orResultInv12 = invBits(z2Val).or(invBits(z1Val)).multiply(runtimeSpec[shift + 11]);
						result1 = result1.add(orResultInv12);

						BigInteger v1 = runtimeSpec[0]
								.add(runtimeSpec[1].multiply(evaluator.getWireValue(z1.valueWire)));
						BigInteger v2 = runtimeSpec[2]
								.add(runtimeSpec[3].multiply(evaluator.getWireValue(z2.valueWire)));

						BigInteger product1 = v1.multiply(v2).add(runtimeSpec[4]);
						BigInteger sum1 = v1.add(v2).add(runtimeSpec[4]);
						BigInteger result2 = sum1;
						if (runtimeSpec[5].equals(BigInteger.ONE)) {
							result2 = product1;
						}

						if (bitwiseOp) {
							evaluator.setWireValue(z3.valueWire, result1.mod(Config.FIELD_PRIME));
						} else {
							evaluator.setWireValue(z3.valueWire, result2.mod(Config.FIELD_PRIME));
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

		Wire activateSplits = new WireArray(selectors).sumAllElements().isEqualTo(0).invAsBit();

		Wire splitOp1 = z1.valueWire.mul(activateSplits);
		Wire splitOp2 = z2.valueWire.mul(activateSplits);

		Wire[] bits1 = splitOp1.getBitWires(BITWIDTH).asArray();
		Wire[] bits2 = splitOp2.getBitWires(BITWIDTH).asArray();

		Wire[] product = new Wire[BITWIDTH];
		Wire[] xor = new Wire[BITWIDTH];
		Wire[] or = new Wire[BITWIDTH];

		Wire[] productInv1 = new Wire[BITWIDTH];
		Wire[] xorInv1 = new Wire[BITWIDTH];
		Wire[] orInv1 = new Wire[BITWIDTH];

		Wire[] productInv2 = new Wire[BITWIDTH];
		Wire[] xorInv2 = new Wire[BITWIDTH];
		Wire[] orInv2 = new Wire[BITWIDTH];

		Wire[] productInv12 = new Wire[BITWIDTH];
		Wire[] xorInv12 = new Wire[BITWIDTH];
		Wire[] orInv12 = new Wire[BITWIDTH];

		Wire oneWire = CircuitGenerator.getActiveCircuitGenerator().getOneWire();

		for (int i = 0; i < BITWIDTH; i++) {
			product[i] = bits1[i].mul(bits2[i]);
			xor[i] = bits1[i].add(bits2[i]).sub(product[i].mul(2));
			or[i] = bits1[i].add(bits2[i]).sub(product[i].mul(1));

			productInv1[i] = bits2[i].sub(product[i]);
			xorInv1[i] = xor[i].invAsBit();
			orInv1[i] = oneWire.sub(bits1[i]).add(product[i]);

			productInv2[i] = bits1[i].sub(product[i]);
			xorInv2[i] = xor[i].invAsBit();
			orInv2[i] = oneWire.sub(bits2[i]).add(product[i]);

			productInv12[i] = or[i].invAsBit();
			xorInv12[i] = xor[i];
			orInv12[i] = product[i].invAsBit();
		}

		Wire[] allResults = new Wire[13];

		allResults[0] = new WireArray(product).packAsBits();
		allResults[1] = new WireArray(xor).packAsBits();
		allResults[2] = new WireArray(or).packAsBits();

		allResults[3] = new WireArray(productInv1).packAsBits();
		allResults[4] = new WireArray(xorInv1).packAsBits();
		allResults[5] = new WireArray(orInv1).packAsBits();

		allResults[6] = new WireArray(productInv2).packAsBits();
		allResults[7] = new WireArray(xorInv2).packAsBits();
		allResults[8] = new WireArray(orInv2).packAsBits();

		allResults[9] = new WireArray(productInv12).packAsBits();
		allResults[10] = new WireArray(xorInv12).packAsBits();
		allResults[11] = new WireArray(orInv12).packAsBits();

		Wire c2_z1 = c2.mul(z1.valueWire);
		Wire c4_z2 = c4.mul(z2.valueWire);
		Wire leftSum = c1.add(c2_z1);
		Wire rightSum = c3.add(c4_z2);
		Wire product1 = leftSum.mul(rightSum).add(c5);
		Wire sum1 = leftSum.add(rightSum).add(c5);
		allResults[12] = sum1.add(opSelector.mul(product1.sub(sum1)));

		Wire tmp = allResults[12].mul(activateSplits.invAsBit());
		for (int i = 0; i < 12; i++) {
			tmp = tmp.add(allResults[i].mul(selectors[i]));
		}
		CircuitGenerator.getActiveCircuitGenerator().addEqualityAssertion(z3.valueWire, tmp,
				"Assertion in bitwise op ");
	}

	public int getOperationOrder() {
		return runtimeOperationOrder;
	}

	public void setArithmeticOperationTypeType(OperationType operationType) {
		BigInteger zero = BigInteger.ZERO;
		BigInteger one = BigInteger.ONE;
		BigInteger negOne = Config.FIELD_PRIME.subtract(BigInteger.ONE);
		BigInteger two = one.add(one);
		BigInteger twoInverse = two.modInverse(Config.FIELD_PRIME);

		BigInteger negTwo = Config.FIELD_PRIME.subtract(two);
		BigInteger negTwoInverse = negTwo.modInverse(Config.FIELD_PRIME);

		BigInteger selector1 = null;
		BigInteger[] constSet1 = null;
		if (operationType == OperationType.add) {
			selector1 = zero;
			constSet1 = new BigInteger[] { zero, one, zero, one, zero };
		}
		if (operationType == OperationType.mul) {
			selector1 = one;
			constSet1 = new BigInteger[] { zero, one, zero, one, zero };
		}
		if (operationType == OperationType.subtract) {
			selector1 = zero;
			constSet1 = new BigInteger[] { zero, one, zero, negOne, zero };
		}
		if (operationType == OperationType.xor) {
			selector1 = one;
			constSet1 = new BigInteger[] { one, negTwo, negTwoInverse, one, twoInverse };
		}
		if (operationType == OperationType.or) {
			selector1 = one;
			constSet1 = new BigInteger[] { one, negOne, negOne, one, one };
		}

		register();
		runtimeSpec = new BigInteger[] { constSet1[0], constSet1[1], constSet1[2], constSet1[3], constSet1[4],
				selector1, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero };
	}

	public void setBitwiseOperationType(BitwiseOperationType operation) {

		runtimeSpec = new BigInteger[6 + 12];
		Arrays.fill(runtimeSpec, BigInteger.ZERO);
		int index = -1;
		int shift = 6;
		switch (operation) {
		case and:
			index = shift + 0;
			break;
		case xor:
			index = shift + 1;
			break;
		case or:
			index = shift + 2;
			break;

		case andInv1:
			index = shift + 3;
			break;
		case xorInv1:
			index = shift + 4;
			break;
		case orInv1:
			index = shift + 5;
			break;

		case andInv2:
			index = shift + 6;
			break;
		case xorInv2:
			index = shift + 7;
			break;
		case orInv2:
			index = shift + 8;
			break;

		case andInv12:
			index = shift + 9;
			break;
		case xorInv12:
			index = shift + 10;
			break;
		case orInv12:
			index = shift + 11;
			break;

		default:
			break;
		}
		register();
		runtimeSpec[index] = BigInteger.ONE;
	}

	public void useAsSplit(int[] splitInfo) {
		if (splitInfo.length != 2) {
			throw new IllegalArgumentException();
		}
		this.splitInfo = splitInfo;
		BigInteger zero = BigInteger.ZERO;
		BigInteger one = BigInteger.ONE;

		runtimeSpec = new BigInteger[] { zero, one, zero, one.shiftLeft(splitInfo[0]), zero, zero, zero, zero, zero,
				zero, zero, zero, zero, zero, zero, zero, zero, zero };

		register();

	}

	private static BigInteger invBits(BigInteger x) {
		BigInteger r = BigInteger.valueOf(~x.intValue() & 0x00000000ffffffffL);
		return r;
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

	public int[] getSplitInfo() {
		return splitInfo;
	}

	public void setSplitInfo(int[] splitInfo) {
		this.splitInfo = splitInfo;
	}

	public void register() {
		runtimeOperationOrder = UniversalCircuitGenerator.globalRuntimeCounter++;
	}

}
