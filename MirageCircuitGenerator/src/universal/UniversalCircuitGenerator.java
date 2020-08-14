/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package universal;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

import jsnark.circuit.config.Config;
import jsnark.circuit.eval.CircuitEvaluator;
import jsnark.circuit.eval.Instruction;
import jsnark.circuit.structure.CircuitGenerator;
import jsnark.circuit.structure.Wire;
import jsnark.util.Util;
import universal.opcodes.OpEntry;
import universal.opcodes.opcode1.BinaryOperation;
import universal.opcodes.opcode1.OperationType;
import universal.opcodes.opcode2.BitwiseOperationType;
import universal.opcodes.opcode2.IntegerBitwiseOperation;
import universal.opcodes.opcode3.Split32Operation;
import universal.opcodes.opcode3.Split32OperationUtil;
import universal.opcodes.opcode4.MemoryLookupOpHandler;

public class UniversalCircuitGenerator extends CircuitGenerator {

	public static int globalRuntimeCounter = 0;
	private int numBinary; // number of supported opcode 1 operations
	private int numBitwise; // number of supported opcode 2 operations
	private int numSplits; // number of supported opcode 3 operations
	private int totalMemorySize;
	private int totalNumberOfLookups; // number of supported opcode 4 operations

	private int stmtSize; // supported statement size
	private final int numRnd = 2; // number of random values needed by the circuit

	private final int zeroConstantIndex = 0;
	private final int oneConstantIndex = 1;
	private int universalIndex = 2;
	private int consumedBinaryOps = 0;
	private int consumedIntegerBitwiseOps = 0;
	private int consumedSplitOps = 0;
	private int consumedStmt = 0;

	private ArrayList<Integer> witnessIndices = new ArrayList<>();
	private ArrayList<Integer> bitsToCheckBuffer = new ArrayList<>();
	private ArrayList<Integer> elementsToCheck32Buffer = new ArrayList<>();

	private ArrayList<OpEntry> allOpEntries = new ArrayList<OpEntry>();
	private OpEntry[] constantEntries; // This is only for 0 and 1 so that they can be used easily for some cases
										// e.g., fill empty unused operations with the zero index.
	private OpEntry[] stmtEntries;
	private OpEntry[] binaryOpEntries;
	private OpEntry[] bitwiseOpEntries;
	private OpEntry[] splitOpEntries;
	private OpEntry[][] memoryEntries;
	private OpEntry[] permutedEntries;
	private Wire[] rndWires;

	private BinaryOperation[] binaryOperations;
	private IntegerBitwiseOperation[] bitwiseOperations;
	private Split32Operation[] splitOperations;
	private MemoryLookupOpHandler memoryLookupOpHandler;

	private UniversalCircuitEvaluator evaluator;

	public UniversalCircuitGenerator(String circuitName, int stmtSize, int numBinary, int numBitwise, int numSplits,
			int totalMemorySize, int totalNumberOfLookups) {
		super(circuitName);
		this.numBinary = numBinary;
		this.numBitwise = numBitwise;
		this.numSplits = numSplits;
		this.stmtSize = stmtSize;
		this.totalMemorySize = totalMemorySize;
		this.totalNumberOfLookups = totalNumberOfLookups;
	}

	public UniversalCircuitGenerator(String circuitName, int stmtSize, int budget) {
		super(circuitName);
		this.stmtSize = stmtSize;
		
		// TODO: revisit numbers after circuit modifications
		int share = budget / 7;
		numBinary = share / 26 * 2;
		numBitwise = share / 135 * 2;
		numSplits = share / 330 * 2;
		totalNumberOfLookups = share / 55;
		this.totalMemorySize = totalNumberOfLookups;

	}


	public void setUniversalCircuitEvaluator(UniversalCircuitEvaluator evaluator) {
		this.evaluator = evaluator;
	}

	@Override
	protected void buildCircuit() {

		int numOfPermutationInput = 2 + stmtSize + numBinary * 3 + numBitwise * 3
				+ numSplits * Split32Operation.NUM_ENTRIES + +totalNumberOfLookups * 3;
		constantEntries = new OpEntry[2];

		constantEntries[0] = new OpEntry(zeroWire, zeroWire);
		constantEntries[1] = new OpEntry(oneWire, oneWire);
		allOpEntries.add(constantEntries[0]);
		allOpEntries.add(constantEntries[1]);
		rndWires = createRndWireArray(numRnd);

		stmtEntries = new OpEntry[stmtSize];
		for (int i = 0; i < stmtSize; i++) {
			stmtEntries[i] = new OpEntry(true);
			allOpEntries.add(stmtEntries[i]);

		}

		binaryOpEntries = new OpEntry[numBinary * 3];
		for (int i = 0; i < numBinary * 3; i++) {
			binaryOpEntries[i] = new OpEntry(false);
			allOpEntries.add(binaryOpEntries[i]);

		}

		bitwiseOpEntries = new OpEntry[numBitwise * 3];
		for (int i = 0; i < numBitwise * 3; i++) {
			bitwiseOpEntries[i] = new OpEntry(false);
			allOpEntries.add(bitwiseOpEntries[i]);

		}

		splitOpEntries = new OpEntry[numSplits * Split32Operation.NUM_ENTRIES];
		for (int i = 0; i < numSplits * Split32Operation.NUM_ENTRIES; i++) {
			splitOpEntries[i] = new OpEntry(false);
			allOpEntries.add(splitOpEntries[i]);
		}

		memoryEntries = new OpEntry[totalNumberOfLookups][3];
		for (int i = 0; i < totalNumberOfLookups; i++) {
			memoryEntries[i][0] = new OpEntry(false);
			memoryEntries[i][1] = new OpEntry(false);
			memoryEntries[i][2] = new OpEntry(false);
			allOpEntries.add(memoryEntries[i][0]);
			allOpEntries.add(memoryEntries[i][1]);
			allOpEntries.add(memoryEntries[i][2]);
		}

		permutedEntries = new OpEntry[numOfPermutationInput];
		for (int i = 0; i < numOfPermutationInput; i++) {
			permutedEntries[i] = new OpEntry(false);
		}

		binaryOperations = new BinaryOperation[numBinary];
		Wire prev = getZeroWire();
		for (int i = 0; i < numBinary; i++) {
			binaryOperations[i] = new BinaryOperation(binaryOpEntries[3 * i], binaryOpEntries[3 * i + 1],
					binaryOpEntries[3 * i + 2], prev);
			prev = binaryOpEntries[3 * i + 2].valueWire;

		}

		bitwiseOperations = new IntegerBitwiseOperation[numBitwise];
		for (int i = 0; i < numBitwise; i++) {
			bitwiseOperations[i] = new IntegerBitwiseOperation(bitwiseOpEntries[3 * i], bitwiseOpEntries[3 * i + 1],
					bitwiseOpEntries[3 * i + 2], null);
		}

		splitOperations = new Split32Operation[numSplits];

		for (int i = 0; i < numSplits; i++) {
			OpEntry[] bitWires = new OpEntry[32];
			for (int j = 0; j < bitWires.length; j++) {
				bitWires[j] = splitOpEntries[i * Split32Operation.NUM_ENTRIES + j];

			}
			OpEntry[] byteWires = new OpEntry[4];
			for (int j = 0; j < byteWires.length; j++) {
				byteWires[j] = splitOpEntries[i * Split32Operation.NUM_ENTRIES + 34 + j];

			}
			splitOperations[i] = new Split32Operation(bitWires, splitOpEntries[Split32Operation.NUM_ENTRIES * i + 32],
					splitOpEntries[Split32Operation.NUM_ENTRIES * i + 33], byteWires, null);
		}

		OpEntry[] indexEntries = new OpEntry[totalNumberOfLookups];
		OpEntry[] valueEntries = new OpEntry[totalNumberOfLookups];
		OpEntry[] writeFlagEntries = new OpEntry[totalNumberOfLookups];
		for (int i = 0; i < totalNumberOfLookups; i++) {
			indexEntries[i] = memoryEntries[i][0];
			valueEntries[i] = memoryEntries[i][1];
			writeFlagEntries[i] = memoryEntries[i][2];
		}

		memoryLookupOpHandler = new MemoryLookupOpHandler(totalNumberOfLookups, totalMemorySize, rndWires, indexEntries,
				valueEntries, writeFlagEntries);

		specifyProverWitnessComputation(new Instruction() {

			@Override
			public void evaluate(CircuitEvaluator evaluator) {
				for (OpEntry entry : allOpEntries) {
					((UniversalCircuitEvaluator) evaluator).resolveEntry(entry);
				}
				Object[] sorted = allOpEntries.toArray();
				Arrays.sort(sorted);
				for (int i = 0; i < permutedEntries.length; i++) {
					evaluator.setWireValue(permutedEntries[i].indexWire,
							evaluator.getWireValue(((OpEntry) sorted[i]).indexWire));
					evaluator.setWireValue(permutedEntries[i].valueWire,
							evaluator.getWireValue(((OpEntry) sorted[i]).valueWire));
				}
			}

			@Override
			public int getOperationCounter() {
				return Integer.MAX_VALUE - 1;
			}
		});

		checkPermutation();
		checkConsistency();

		specifyProverWitnessComputation(new Instruction() {

			@Override
			public void evaluate(CircuitEvaluator evaluator) {
				for (OpEntry entry : stmtEntries) {
					((UniversalCircuitEvaluator) evaluator).resolveEntry(entry);
				}
			}

			public int getOperationCounter() {
				return consumedBinaryOps + consumedIntegerBitwiseOps + consumedStmt + consumedSplitOps;
			}

		});
	}

	private void checkConsistency() {
		for (int i = 1; i < permutedEntries.length; i++) {
			Wire diff = permutedEntries[i].indexWire.sub(permutedEntries[i - 1].indexWire);
			Wire diffInv = diff.invAsBit();
			addAssertion(permutedEntries[i].valueWire.sub(permutedEntries[i - 1].valueWire), diffInv, zeroWire,
					"consistency assertion (global)");
		}

	}

	private void checkPermutation() {

		Wire product1 = getOneWire();
		Wire product2 = getOneWire();

		Wire r1 = rndWires[0];
		Wire r2 = rndWires[1];

		for (OpEntry entry : allOpEntries) {
			product1 = product1.mul(r1.sub(entry.valueWire.add(entry.indexWire.mul(r2))));
		}

		for (OpEntry entry : permutedEntries) {
			product2 = product2.mul(r1.sub(entry.valueWire.add(entry.indexWire.mul(r2))));
		}
		addEqualityAssertion(product1, product2, "Permutation check global");

	}

	public void prepareForSpecification() {
		this.evaluator = new UniversalCircuitEvaluator(this);
		registerMemory("NULL_MEM", 1);
		initInputAssignment();
	}

	public void finalizeSpecification() {
		specifyRemainingConstraints();

		System.out.println("Total number of records/ops [stmt, op1, op2, op3, op4] = " + stmtSize + "," + numBinary + ","
				+ numBitwise + ", " + numSplits + ", " + totalNumberOfLookups);
		System.out.println(
				"Number of consumed records/ops = " + consumedStmt + "," + consumedBinaryOps + "," + consumedIntegerBitwiseOps
						+ ", " + consumedSplitOps + ", " + memoryLookupOpHandler.getRegisteredInstructions());
		System.out.println("Number of remaining records/ops = " + (stmtSize - consumedStmt) + "," + (numBinary - consumedBinaryOps)
				+ "," + (numBitwise - consumedIntegerBitwiseOps) + ", " + (numSplits - consumedSplitOps) + ", "
				+ (totalNumberOfLookups - memoryLookupOpHandler.getRegisteredInstructions()));

		fillEmpty();
	}

	public void addBitToVerify(int index) {
		bitsToCheckBuffer.add(index);
	}

	public void addElementToVerify32(int index) {
		elementsToCheck32Buffer.add(index);
	}

	private void specifyRemainingConstraints() {
		int i = 0;
		
		// Bits that need to be verified.
		while (i < bitsToCheckBuffer.size()) {
			int j = 0;
			int[] bits = new int[32];
			while (j < 32 && i < bitsToCheckBuffer.size()) {
				bits[j] = bitsToCheckBuffer.get(i);
				j++;
				i++;
			}
			try {
				packBits(bits);
			} catch (ArrayIndexOutOfBoundsException exception) {
				for (int b : bits) {
					addBinaryConstraint(b, b, b, OperationType.mul, OperationType.add, false);
				}
			}
		}

		i = 0;
		// 32-bit elements that need to be verified

		while (i < elementsToCheck32Buffer.size()) {
			int j = 0;
			int[] elements = new int[2];
			while (j < 2 && i < elementsToCheck32Buffer.size()) {
				elements[j] = elementsToCheck32Buffer.get(i);
				j++;
				i++;
			}
			if (j == 2) {
				bitwiseOp(elements[0], elements[1], BitwiseOperationType.xor);
			} else {
				bitwiseOp(elements[0], zeroConstantIndex, BitwiseOperationType.xor);

			}
		}

	}

	private void initInputAssignment() {
		
		// The random values are filled here just for testing.
		evaluator.setWireValue(rndWires, Util.randomBigIntegerArray(rndWires.length, 253));


		evaluator.setUniversalAssignment(BigInteger.ZERO, BigInteger.ZERO);
		evaluator.setUniversalAssignment(BigInteger.ONE, BigInteger.ONE);
		evaluator.setWireValue(constantEntries[0].indexWire, BigInteger.ZERO); 
		evaluator.setWireValue(constantEntries[1].indexWire, BigInteger.ONE); 
	}

	protected void fillEmpty() {

		for (int i = consumedStmt; i < stmtSize; i++) {
			makeStmt(zeroConstantIndex, BigInteger.ZERO);
		}
		for (int i = consumedBinaryOps; i < numBinary; i++) {
			zeroedBinaryOp();
		}
		for (int i = consumedIntegerBitwiseOps; i < numBitwise; i++) {
			zeroBitwiseOp();
		}
		for (int i = consumedSplitOps; i < numSplits; i++) {
			zeroSplitOp32();
		}

		for (int i = memoryLookupOpHandler.getRegisteredInstructions(); i < totalNumberOfLookups; i++) {
			writeToMemory("NULL_MEM", zeroConstantIndex, zeroConstantIndex);
		}

	}

	public void registerMemory(String name, int size) {
		memoryLookupOpHandler.registerMemoryName(name, size);
	}

	public int readFromMemory(String name, int index) {
		int numRegistered = memoryLookupOpHandler.getRegisteredInstructions();
		evaluator.setWireValue(memoryEntries[numRegistered][1].indexWire, universalIndex);
		memoryLookupOpHandler.addReadOperation(name, index);
		return universalIndex++;
	}

	public void writeToMemory(String name, int index, int value) {
//		int numRegistered = memoryLookupOp.registeredInstructions;
//		evaluator.setWireValue(memoryEntries[numRegistered][1].indexWire, universalIndex);
		memoryLookupOpHandler.addWriteOperation(name, index, value);

	}

	public void writeToMemory(String name, int index, int value, int enable) {
//		int numRegistered = memoryLookupOp.registeredInstructions;
//		evaluator.setWireValue(memoryEntries[numRegistered][1].indexWire, universalIndex);
		memoryLookupOpHandler.addConditionalWriteOperation(name, index, value, enable);

	}

	public void makeStmt(int index, BigInteger value) {
		evaluator.setWireValue(stmtEntries[consumedStmt].indexWire, BigInteger.valueOf(index));
		evaluator.setWireValue(stmtEntries[consumedStmt].valueWire, value);
		evaluator.resolveEntry(stmtEntries[consumedStmt]);
		consumedStmt++;
	}

	public void makeStmtOutput(int index) {
		evaluator.setWireValue(stmtEntries[consumedStmt].indexWire, BigInteger.valueOf(index));
		evaluator.resolveEntry(stmtEntries[consumedStmt]);
//		evaluator.setWireValue(stmtEntries[consumedStmt].value, value);
		consumedStmt++;
	}

	public void makeStmtOutputArray(int[] outputs) {
		for (int i = 0; i < outputs.length; i++) {
			makeStmtOutput(outputs[i]);
		}
	}

	public int[] createStmtArray(int n, BigInteger[] values) {
		int[] array = new int[n];
		for (int i = 0; i < array.length; i++) {
			array[i] = universalIndex++;
			evaluator.setWireValue(stmtEntries[consumedStmt].indexWire, BigInteger.valueOf(array[i]));
			evaluator.setWireValue(stmtEntries[consumedStmt].valueWire, values[i]);
			evaluator.resolveEntry(stmtEntries[consumedStmt]);
			consumedStmt++;
		}
		return array;
	}

	public int mulBinaryOp(int index1, int index2) {
		binaryOperations[consumedBinaryOps].setType(OperationType.mul, OperationType.add, false);
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps].indexWire, BigInteger.valueOf(index1));
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 1].indexWire, BigInteger.valueOf(index2));
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 2].indexWire,
				BigInteger.valueOf(universalIndex));

		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps]);
		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps + 1]);

		consumedBinaryOps++;
		return universalIndex++;
	}

	public void zeroBitwiseOp() {
		bitwiseOperations[consumedIntegerBitwiseOps].setBitwiseOperationType(BitwiseOperationType.and);
		evaluator.setWireValue(bitwiseOpEntries[3 * consumedIntegerBitwiseOps].indexWire,
				BigInteger.valueOf(zeroConstantIndex));
		evaluator.setWireValue(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 1].indexWire,
				BigInteger.valueOf(zeroConstantIndex));
		evaluator.setWireValue(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 2].indexWire,
				BigInteger.valueOf(zeroConstantIndex));

		evaluator.resolveEntry(bitwiseOpEntries[3 * consumedIntegerBitwiseOps]);
		evaluator.resolveEntry(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 1]);
		evaluator.resolveEntry(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 2]);

		consumedIntegerBitwiseOps++;
	}

	public int bitwiseOp(int index1, int index2, BitwiseOperationType op) {
		bitwiseOperations[consumedIntegerBitwiseOps].setBitwiseOperationType(op);
		evaluator.setWireValue(bitwiseOpEntries[3 * consumedIntegerBitwiseOps].indexWire, BigInteger.valueOf(index1));
		evaluator.setWireValue(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 1].indexWire,
				BigInteger.valueOf(index2));
		evaluator.setWireValue(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 2].indexWire,
				BigInteger.valueOf(universalIndex));

		evaluator.resolveEntry(bitwiseOpEntries[3 * consumedIntegerBitwiseOps]);
		evaluator.resolveEntry(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 1]);
		consumedIntegerBitwiseOps++;
		return universalIndex++;
	}

	public int useBitwiseOpAsBinaryArithmeticOp(int index1, int index2, OperationType op) {
		bitwiseOperations[consumedIntegerBitwiseOps].setArithmeticOperationTypeType(op);
		evaluator.setWireValue(bitwiseOpEntries[3 * consumedIntegerBitwiseOps].indexWire, BigInteger.valueOf(index1));
		evaluator.setWireValue(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 1].indexWire,
				BigInteger.valueOf(index2));
		evaluator.setWireValue(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 2].indexWire,
				BigInteger.valueOf(universalIndex));

		evaluator.resolveEntry(bitwiseOpEntries[3 * consumedIntegerBitwiseOps]);
		evaluator.resolveEntry(bitwiseOpEntries[3 * consumedIntegerBitwiseOps + 1]);
		consumedBinaryOps++;
		return universalIndex++;
	}

	public void zeroedBinaryOp() {
		binaryOperations[consumedBinaryOps].setType(OperationType.add, OperationType.add, false);
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps].indexWire, BigInteger.valueOf(zeroConstantIndex));
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 1].indexWire,
				BigInteger.valueOf(zeroConstantIndex));
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 2].indexWire,
				BigInteger.valueOf(zeroConstantIndex));
		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps]);
		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps + 1]);
		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps + 2]);
		consumedBinaryOps++;
		return;
	}

	public int addBinaryOp(int index1, int index2) {
		binaryOperations[consumedBinaryOps].setType(OperationType.add, OperationType.add, false);
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps].indexWire, BigInteger.valueOf(index1));
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 1].indexWire, BigInteger.valueOf(index2));
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 2].indexWire,
				BigInteger.valueOf(universalIndex));
		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps]);
		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps + 1]);
		consumedBinaryOps++;
		return universalIndex++;
	}

	public int isGreaterThan32(int index1, int index2) {
		int sum2 = customBinaryOp(index1, index2, OperationType.subtract, OperationType.add, false);
		setRuntimeSpecEntryForBinaryOp(0, BigInteger.ONE.shiftLeft(32));
		setRuntimeSpecEntryForBinaryOp(4, Config.FIELD_PRIME.subtract(BigInteger.ONE));

		int[] sum2Splitted = splitBinary(sum2, new int[] { 32, 1 });
		addElementToVerify32(sum2Splitted[0]);
		addBitToVerify(sum2Splitted[1]);
		return sum2Splitted[1];

//		return customBinary(evaluator, getOneIndex(), sum2Splitted[1], Operation.subtract, Operation.add, false);
	}

	public int isGreaterThan64(int index1, int index2) {

		int sum2 = customBinaryOp(index1, index2, OperationType.subtract, OperationType.add, false);
		setRuntimeSpecEntryForBinaryOp(0, BigInteger.ONE.shiftLeft(64));
		setRuntimeSpecEntryForBinaryOp(4, Config.FIELD_PRIME.subtract(BigInteger.ONE));

		int[] sum2Splitted = splitBinary(sum2, new int[] { 64, 1 });
		forceBitwidth(sum2Splitted[0], 64);
		addBitToVerify(sum2Splitted[1]);
		return sum2Splitted[1];
	}

	public int isEqual(int index1, int index2) {
		return customBinaryOp(index1, index2, OperationType.isEqual, OperationType.add, false);
	}

	public int isNotEqual(int index1, int index2) {
		return customBinaryOp(index1, index2, OperationType.isNotEqual, OperationType.add, false);
	}

	public int muxSelector(int index1, int index2, int selector) {
		int sub = customBinaryOp(index2, index1, OperationType.subtract, OperationType.add, false);
		int prod = mulBinaryOp(sub, selector);
		return addBinaryOp(index1, prod);
	}

	public int makeConstant(int value) {
		int v = mulBinaryOp(oneConstantIndex, oneConstantIndex);
		binaryOperations[consumedBinaryOps - 1].getRuntimeSpec()[1] = BigInteger.valueOf(value);
		return v;
	}

	public int makeConstant(BigInteger value) {
		int v = mulBinaryOp(oneConstantIndex, oneConstantIndex);
		binaryOperations[consumedBinaryOps - 1].getRuntimeSpec()[1] = value;
		return v;
	}

	public int makeWitness() {
		witnessIndices.add(universalIndex);
		return universalIndex++;
	}

	public int[] makeWitnessArray(int n) {
		int[] w = new int[n];
		for (int i = 0; i < n; i++) {
			w[i] = makeWitness();
		}
		return w;
	}

	public int[][] makeWitness2DArray(int n1, int n2) {
		int[][] w = new int[n1][n2];
		for (int i = 0; i < n1; i++) {
			w[i] = makeWitnessArray(n2);
		}
		return w;
	}

	public int[] splitBinary(int index, int[] splitInfo) {

		binaryOperations[consumedBinaryOps].useAsSplit(splitInfo);
		int[] splitted = new int[] { universalIndex++, universalIndex++ };
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps].indexWire, BigInteger.valueOf(splitted[0]));
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 1].indexWire, BigInteger.valueOf(splitted[1]));

		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 2].indexWire, index);

		consumedBinaryOps++;
		return splitted;
	}

	public void addBinaryConstraint(int index1, int index2, int index3, OperationType op1, OperationType op2,
			boolean usePrev) {

		binaryOperations[consumedBinaryOps].setType(op1, op2, usePrev);

		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps].indexWire, BigInteger.valueOf(index1));
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 1].indexWire, BigInteger.valueOf(index2));

		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 2].indexWire, BigInteger.valueOf(index3));

		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps]);
		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps + 1]);
		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps + 2]);

		consumedBinaryOps++;
	}

	public int customBinaryOp(int index1, int index2, OperationType op1, OperationType op2, boolean usePrev) {
		binaryOperations[consumedBinaryOps].setType(op1, op2, usePrev);

		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps].indexWire, BigInteger.valueOf(index1));
		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 1].indexWire, BigInteger.valueOf(index2));

		evaluator.setWireValue(binaryOpEntries[3 * consumedBinaryOps + 2].indexWire,
				BigInteger.valueOf(universalIndex));

		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps]);
		evaluator.resolveEntry(binaryOpEntries[3 * consumedBinaryOps + 1]);
		consumedBinaryOps++;

		return universalIndex++;
	}

	public int packBits(int[] bits) {

		if (bits.length > 32) {
			throw new UnsupportedOperationException();
		}

		splitOperations[consumedSplitOps].setOperation(true, Split32OperationUtil.getSplitCoefficients(),
				Split32OperationUtil.getSplitCoefficients());
		if (bits.length < 32) {
			bits = Util.padIntArray(bits, 32, zeroConstantIndex);
		}

		for (int i = 0; i < 32; i++) {
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + i].indexWire,
					BigInteger.valueOf(bits[i]));
		}

		int o1 = universalIndex;
		int o2 = universalIndex + 1;

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 32].indexWire,
				BigInteger.valueOf(o1));

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 33].indexWire,
				BigInteger.valueOf(o2));

		for (int i = 0; i < 4; i++) {
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 34 + i].indexWire,
					BigInteger.valueOf(o2 + 1 + i));
		}

		universalIndex = universalIndex + 6;
		consumedSplitOps++;
		return o1;
	}

	public void zeroSplitOp32() {

		splitOperations[consumedSplitOps].setOperation(true, null, null);

		for (int i = 0; i < 32; i++) {
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + i].indexWire,
					BigInteger.valueOf(zeroConstantIndex));
		}

		int o1 = zeroConstantIndex;
		int o2 = zeroConstantIndex;

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 32].indexWire,
				BigInteger.valueOf(o1));

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 33].indexWire,
				BigInteger.valueOf(o2));

		for (int i = 0; i < 4; i++) {
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 34 + i].indexWire,
					BigInteger.valueOf(zeroConstantIndex));
		}
		consumedSplitOps++;
	}

	public int[] customOp3(int[] elements, boolean forceBinary, BigInteger[] set1, BigInteger[] set2) {

		if (elements.length > 32) {
			throw new UnsupportedOperationException();
		}

		splitOperations[consumedSplitOps].setOperation(true, set1, set2);
		if (elements.length < 32) {
			elements = Util.padIntArray(elements, 32, zeroConstantIndex);
		}

		for (int i = 0; i < 32; i++) {
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + i].indexWire,
					BigInteger.valueOf(elements[i]));
		}

		int o1 = universalIndex;
		int o2 = universalIndex + 1;

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 32].indexWire,
				BigInteger.valueOf(o1));

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 33].indexWire,
				BigInteger.valueOf(o2));

		for (int i = 0; i < 4; i++) {
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 34 + i].indexWire,
					BigInteger.valueOf(o2 + 1 + i));
		}

		universalIndex = universalIndex + 6;
		consumedSplitOps++;
		return new int[] { o1, o2 };
	}

	public int[] split32ToBytes(int index, int numBits) {
		if (numBits != 32)
			throw new UnsupportedOperationException();

		splitOperations[consumedSplitOps].setOperation(true, Split32OperationUtil.getSplitCoefficients(),
				Split32OperationUtil.getSplitCoefficients());
		int[] bits = new int[32];

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 32].indexWire,
				BigInteger.valueOf(index));

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 33].indexWire,
				BigInteger.valueOf(universalIndex++));

		for (int i = 0; i < 32; i++) {
			bits[i] = universalIndex++;
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + i].indexWire,
					BigInteger.valueOf(bits[i]));

		}

		int[] bytes = new int[4];
		for (int i = 0; i < 4; i++) {
			bytes[i] = universalIndex++;
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 34 + i].indexWire,
					BigInteger.valueOf(bytes[i]));

		}
		consumedSplitOps++;
		return bytes;
	}

	public int[] split32ToBitsAndApplySet(int index, int numBits, BigInteger[] set2) {
		if (numBits != 32)
			throw new UnsupportedOperationException();

		splitOperations[consumedSplitOps].setOperation(true, Split32OperationUtil.getSplitCoefficients(), set2);
		int[] result = new int[33];

//		System.out.println("Setting Value1 = " + splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 32].indexWire);

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 32].indexWire,
				BigInteger.valueOf(index));

		int z2Index = universalIndex++;
		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 33].indexWire,
				BigInteger.valueOf(z2Index));

		for (int i = 0; i < 32; i++) {
			result[i] = universalIndex++;
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + i].indexWire,
					BigInteger.valueOf(result[i]));

		}
		result[32] = z2Index;

		int[] bytes = new int[4];
		for (int i = 0; i < 4; i++) {
			bytes[i] = universalIndex++;
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 34 + i].indexWire,
					BigInteger.valueOf(bytes[i]));

		}

		consumedSplitOps++;
		return result;
	}

	public int[] split32ToBits(int index, int numBits) {
		if (numBits != 32)
			throw new UnsupportedOperationException();

		splitOperations[consumedSplitOps].setOperation(true, Split32OperationUtil.getSplitCoefficients(),
				Split32OperationUtil.getSplitCoefficients());
		int[] bits = new int[32];

//		System.out.println("Setting Value1 = " + splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 32].indexWire);

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 32].indexWire,
				BigInteger.valueOf(index));

//		System.out.println("Setting Value2 = " + splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 33].indexWire);

		evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 33].indexWire,
				BigInteger.valueOf(universalIndex++));

		for (int i = 0; i < 32; i++) {
			bits[i] = universalIndex++;
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + i].indexWire,
					BigInteger.valueOf(bits[i]));

		}

		int[] bytes = new int[4];
		for (int i = 0; i < 4; i++) {
//			System.out.println("Setting wire = " + splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 34 + i].indexWire);

			bytes[i] = universalIndex++;
			evaluator.setWireValue(splitOpEntries[Split32Operation.NUM_ENTRIES * consumedSplitOps + 34 + i].indexWire,
					BigInteger.valueOf(bytes[i]));

		}

		consumedSplitOps++;
		return bits;
	}

	public int getZeroIndex() {
		return zeroConstantIndex;
	}

	public int getOneIndex() {
		return oneConstantIndex;
	}

	public BinaryOperation[] getBinaryOperations() {
		return binaryOperations;
	}

	public IntegerBitwiseOperation[] getBitwiseOperations() {
		return bitwiseOperations;
	}

	public Split32Operation[] getSplitOperations() {
		return splitOperations;
	}

	public MemoryLookupOpHandler getMemoryLookupOpHandler() {
		return memoryLookupOpHandler;
	}

	public void setRuntimeSpecEntryForBinaryOp(int index, BigInteger c) {
		binaryOperations[consumedBinaryOps - 1].getRuntimeSpec()[index] = c;
	}

	public void forceBitwidth(int index, int bitwidth) {
		if (bitwidth % 32 != 0 || bitwidth <= 0) {
			throw new IllegalArgumentException("not supported using this method yet");
		} else {
			if (bitwidth == 32) {
				addElementToVerify32(index);
			} else {
				if (bitwidth % 64 == 0) {
//				int numIterations = bitwidth/32;
					int[] splitted = splitBinary(index, new int[] { bitwidth / 2, bitwidth / 2 });
					forceBitwidth(splitted[0], bitwidth / 2);
					forceBitwidth(splitted[1], bitwidth / 2);
				} else {
					if ((bitwidth - 32) % 64 != 0) {
						System.err.println("Warning - in force bitwidth");
					}
					int[] splitted = splitBinary(index, new int[] { bitwidth - 32, 32 });
					forceBitwidth(splitted[0], bitwidth - 32);
					forceBitwidth(splitted[1], 32);
				}
			}
		}

	}

	public UniversalCircuitEvaluator getCircuitEvaluator() {
		return evaluator;
	}

	public ArrayList<Integer> getWitnessIndices() {
		return witnessIndices;
	}

}
