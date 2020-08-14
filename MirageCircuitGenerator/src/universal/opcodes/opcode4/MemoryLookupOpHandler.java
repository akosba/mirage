/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package universal.opcodes.opcode4;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Hashtable;

import jsnark.circuit.eval.CircuitEvaluator;
import jsnark.circuit.eval.Instruction;
import jsnark.circuit.structure.CircuitGenerator;
import jsnark.circuit.structure.Wire;
import universal.UniversalCircuitEvaluator;
import universal.UniversalCircuitGenerator;
import universal.opcodes.OpEntry;

public class MemoryLookupOpHandler {

	private UniversalCircuitGenerator generator;

	private int totalNumberOfLookups = 0;
	private int totalMemorySize = 0;

	private int reservedSize = 0;

	private Hashtable<String, Integer> memoryIdToShiftMap = new Hashtable<>();
	private OpEntry[] indexEntries;
	private OpEntry[] valueEntries;
	private OpEntry[] writeFlagEntries;
	private Wire[] opCountWires;

	private Wire[] permutedIndecies;
	private Wire[] permutedValues;
	private Wire[] permutedWriteFlags;
	private Wire[] permutedOpCount;

	private BigInteger[] runtimeVals;
	private Wire[] rndWires;
	private Wire[] shifts;

	private Instruction[] lookupInstructions;
	private int[] registerationCounters;
	private int registeredInstructions = 0;

	private int indexBitwidth;
	private int opCounterBitwidth;

	public MemoryLookupOpHandler(int totalNumberOfLookups, int totalMemorySize, Wire[] rndWires, OpEntry[] indexEntries,
			OpEntry[] valueEntries, OpEntry[] writeFlagEntries) {

		generator = (UniversalCircuitGenerator) CircuitGenerator.getActiveCircuitGenerator();
		this.totalNumberOfLookups = totalNumberOfLookups;
		this.totalMemorySize = totalMemorySize;

		indexBitwidth = (int) Math.ceil(Math.log(totalMemorySize) / Math.log(2));
		opCounterBitwidth = (int) Math.ceil(Math.log(totalNumberOfLookups) / Math.log(2));
		this.indexEntries = indexEntries;
		this.valueEntries = valueEntries;
		this.writeFlagEntries = writeFlagEntries;

		permutedIndecies = generator.createProverWitnessWireArray(totalNumberOfLookups);
		permutedValues = generator.createProverWitnessWireArray(totalNumberOfLookups);
		permutedWriteFlags = generator.createProverWitnessWireArray(totalNumberOfLookups);
		permutedOpCount = generator.createProverWitnessWireArray(totalNumberOfLookups);
		registerationCounters = new int[totalNumberOfLookups];
		runtimeVals = new BigInteger[totalMemorySize];
		Arrays.fill(runtimeVals, BigInteger.ZERO);
		this.rndWires = rndWires;

		if (totalMemorySize != 0)
			buildCircuit();
	}

	public void addReadOperation(String memoryId, int index) {
//		System.out.println("SHIFT = " + memoryIdToShiftMap.get(memoryId));
		UniversalCircuitEvaluator evaluator = generator.getCircuitEvaluator();
		evaluator.setWireValue(shifts[registeredInstructions], memoryIdToShiftMap.get(memoryId));
		evaluator.setWireValue(indexEntries[registeredInstructions].indexWire, index);
		evaluator.setWireValue(writeFlagEntries[registeredInstructions].indexWire, generator.getZeroIndex());
		registerOneLookup();
	}

	public void addWriteOperation(String memoryId, int index, int value) {
		UniversalCircuitEvaluator evaluator = generator.getCircuitEvaluator();

		evaluator.setWireValue(shifts[registeredInstructions], memoryIdToShiftMap.get(memoryId));
		evaluator.setWireValue(indexEntries[registeredInstructions].indexWire, index);
		evaluator.setWireValue(valueEntries[registeredInstructions].indexWire, value);
		evaluator.setWireValue(writeFlagEntries[registeredInstructions].indexWire, generator.getOneIndex());
		registerOneLookup();
	}

	public void addConditionalWriteOperation(String name, int index, int value, int enable) {

		int witness = generator.makeWitness();
		int order = UniversalCircuitGenerator.globalRuntimeCounter++;
		generator.specifyProverWitnessComputation(new Instruction() {

			@Override
			public void evaluate(CircuitEvaluator evaluator) {

				UniversalCircuitEvaluator univEvaluator = ((UniversalCircuitEvaluator) evaluator);
//				if (runtimeVals.length <= univEvaluator.getValueOfIndex(index).add(BigInteger.valueOf(memoryIdToShiftMap.get(name))).intValue()) {
//					univEvaluator.setUniversalAssignment(BigInteger.valueOf(witness), BigInteger.ZERO);
//				} else {
				univEvaluator.setUniversalAssignment(BigInteger.valueOf(witness), runtimeVals[univEvaluator
						.getValueOfIndex(index).add(BigInteger.valueOf(memoryIdToShiftMap.get(name))).intValue()]);
//				}
			}

			@Override
			public int getOperationCounter() {
				// TODO Auto-generated method stub
				return order;
			}
		});
		UniversalCircuitEvaluator evaluator = generator.getCircuitEvaluator();

		evaluator.setWireValue(shifts[registeredInstructions], memoryIdToShiftMap.get(name));
		evaluator.setWireValue(indexEntries[registeredInstructions].indexWire, index);

		int muxed = generator.muxSelector(witness, value, enable);

		evaluator.setWireValue(valueEntries[registeredInstructions].indexWire, muxed);
		evaluator.setWireValue(writeFlagEntries[registeredInstructions].indexWire, enable);
		registerOneLookup();
	}

	private void registerOneLookup() {
		registerationCounters[registeredInstructions] = UniversalCircuitGenerator.globalRuntimeCounter++;
		registeredInstructions++;
	}

	private void buildCircuit() {

		shifts = generator.createSpecWireArray(totalNumberOfLookups);
		opCountWires = new Wire[totalNumberOfLookups];
		for (int i = 0; i < opCountWires.length; i++) {
			opCountWires[i] = generator.createConstantWire(i);
		}

		lookupInstructions = new Instruction[totalNumberOfLookups];
		for (int i = 0; i < totalNumberOfLookups; i++) {
			final int lookUpIndex = i;
			lookupInstructions[i] = new Instruction() {
				@Override
				public void evaluate(CircuitEvaluator evaluator) {
					UniversalCircuitEvaluator univEvaluator = ((UniversalCircuitEvaluator) evaluator);

					univEvaluator.resolveEntry(indexEntries[lookUpIndex]);
					univEvaluator.resolveEntry(valueEntries[lookUpIndex]);
					univEvaluator.resolveEntry(writeFlagEntries[lookUpIndex]);

					BigInteger v1 = evaluator.getWireValue(indexEntries[lookUpIndex].valueWire);
					BigInteger v2 = evaluator.getWireValue(valueEntries[lookUpIndex].valueWire);
					BigInteger v3 = evaluator.getWireValue(writeFlagEntries[lookUpIndex].valueWire);

					if (v3.equals(BigInteger.ZERO)) {
						if (runtimeVals[v1.add(evaluator.getWireValue(shifts[lookUpIndex])).intValue()] == null)
							System.out.println("Warning --  assigning with a NULL");
						evaluator.setWireValue(valueEntries[lookUpIndex].valueWire,
								runtimeVals[v1.add(evaluator.getWireValue(shifts[lookUpIndex])).intValue()]);
					} else {
						runtimeVals[v1.add(evaluator.getWireValue(shifts[lookUpIndex])).intValue()] = v2;
					}

					univEvaluator.resolveEntry(indexEntries[lookUpIndex]);
					univEvaluator.resolveEntry(valueEntries[lookUpIndex]);
					univEvaluator.resolveEntry(writeFlagEntries[lookUpIndex]);

				}

				@Override
				public int getOperationCounter() {
					return registerationCounters[lookUpIndex];
				}
			};
			generator.specifyProverWitnessComputation(lookupInstructions[i]);
		}

		Wire[] values1 = new Wire[totalNumberOfLookups];
		Wire[] values2 = new Wire[totalNumberOfLookups];

		Wire r1 = rndWires[0];
		Wire r1_2 = r1.mul(r1);
		Wire r1_3 = r1.mul(r1_2);
		Wire r2 = rndWires[1];

		Wire prod1 = generator.getOneWire();
		Wire prod2 = generator.getOneWire();

		generator.specifyProverWitnessComputation(new Instruction() {
			@Override
			public void evaluate(CircuitEvaluator evaluator) {

				MemoryConsistencyRecord[] array = new MemoryConsistencyRecord[totalNumberOfLookups];

				for (int i = 0; i < totalNumberOfLookups; i++) {
					array[i] = new MemoryConsistencyRecord();
					array[i].op = evaluator.getWireValue(writeFlagEntries[i].valueWire);
					array[i].counter = evaluator.getWireValue(opCountWires[i]);
					array[i].index = evaluator.getWireValue(indexEntries[i].valueWire)
							.add(evaluator.getWireValue(shifts[i]));
					array[i].data = new BigInteger[] { evaluator.getWireValue(valueEntries[i].valueWire) };
				}

				ArrayIndexComparator comparator = new ArrayIndexComparator(array);
				Integer[] indexes = comparator.createIndexArray();
				Arrays.sort(indexes, comparator);

				int[] permutation = new int[totalNumberOfLookups];
				for (int i = 0; i < totalNumberOfLookups; i++) {
					permutation[indexes[i]] = i;
				}
				Arrays.sort(array);

				for (int i = 0; i < totalNumberOfLookups; i++) {

					evaluator.setWireValue(permutedWriteFlags[i], array[i].op);
					evaluator.setWireValue(permutedOpCount[i], array[i].counter);
					evaluator.setWireValue(permutedIndecies[i], array[i].index);
					for (int j = 0; j < 1; j++) {
						evaluator.setWireValue(permutedValues[i], array[i].data[j]);
					}
				}
			}
		});

		for (int i = 0; i < totalNumberOfLookups; i++) {
			values1[i] = valueEntries[i].valueWire;
			values1[i] = values1[i].add(indexEntries[i].valueWire.add(shifts[i]).mul(r1));
			values1[i] = values1[i].add(writeFlagEntries[i].valueWire.mul(r1_2));
			values1[i] = values1[i].add(opCountWires[i].mul(r1_3));
			prod1 = prod1.mul(r2.sub(values1[i]));

			values2[i] = permutedValues[i];
			values2[i] = values2[i].add(permutedIndecies[i].mul(r1));
			values2[i] = values2[i].add(permutedWriteFlags[i].mul(r1_2));
			values2[i] = values2[i].add(permutedOpCount[i].mul(r1_3));
			prod2 = prod2.mul(r2.sub(values2[i]));
		}
		generator.addEqualityAssertion(prod1, prod2);

		Wire isRead;
		if (totalNumberOfLookups > 0) {
			isRead = permutedWriteFlags[0].invAsBit();
			generator.addZeroAssertion(isRead.mul(permutedValues[0].sub(generator.getZeroWire())),
					"Checking equality with zero if first operation is read");
		}

//		generator.printState("before consistency check");
		for (int i = 1; i < totalNumberOfLookups; i++) {
			Wire greaterIndex = permutedIndecies[i].isGreaterThan(permutedIndecies[i - 1], indexBitwidth);

			Wire equalIndex = permutedIndecies[i].isEqualTo(permutedIndecies[i - 1]);
			Wire greaterOpCounter = permutedOpCount[i].isGreaterThan(permutedOpCount[i - 1], opCounterBitwidth);

			generator.addOneAssertion(greaterIndex.add(equalIndex.mul(greaterOpCounter)),
					"Either a greater index or equal index and higher op counter");

			isRead = permutedWriteFlags[i].invAsBit();
			generator.addZeroAssertion(isRead.mul(equalIndex).mul(permutedValues[i].sub(permutedValues[i - 1])),
					"consistent data items");

			// TODO revisit overflow safety check
		}

	}

	private static class MemoryConsistencyRecord implements Comparable<MemoryConsistencyRecord> {
		private BigInteger op;
		private BigInteger index;
		private BigInteger counter;
		private BigInteger[] data;

		@Override
		public int compareTo(MemoryConsistencyRecord o) {
			MemoryConsistencyRecord record = (MemoryConsistencyRecord) o;
			if (index.compareTo(record.index) < 0)
				return -1;
			else if (index.compareTo(record.index) > 0)
				return 1;
			else {
				return counter.compareTo(record.counter);
			}
		}
	}

	private static class ArrayIndexComparator implements Comparator<Integer> {
		private final MemoryConsistencyRecord[] array;

		public ArrayIndexComparator(MemoryConsistencyRecord[] array) {
			this.array = array;
		}

		public Integer[] createIndexArray() {
			Integer[] indexes = new Integer[array.length];
			for (int i = 0; i < array.length; i++) {
				indexes[i] = i;
			}
			return indexes;
		}

		@Override
		public int compare(Integer index1, Integer index2) {
			return array[index1].compareTo(array[index2]);
		}
	}

	public void registerMemoryName(String name, int size) {
		memoryIdToShiftMap.put(name, reservedSize);
		reservedSize += size;
		if (reservedSize > totalMemorySize && totalMemorySize != 0) {
			throw new IllegalArgumentException("Cannot allocate more space for memory");
		}
	}

	public int getRegisteredInstructions() {
		return registeredInstructions;
	}

}
