/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package examples.auxiliary;

import java.math.BigInteger;
import java.util.Arrays;

import universal.UniversalCircuitGenerator;
import universal.opcodes.opcode1.OperationType;
import universal.opcodes.opcode2.BitwiseOperationType;
import universal.opcodes.opcode3.Split32OperationUtil;

public class SHA256 {

	private static final long H[] = { 0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L,
			0xa54ff53aL, 0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L };

	private static final long K[] = { 0x428a2f98L, 0x71374491L, 0xb5c0fbcfL,
			0xe9b5dba5L, 0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
			0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L, 0x72be5d74L,
			0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L, 0xe49b69c1L, 0xefbe4786L,
			0x0fc19dc6L, 0x240ca1ccL, 0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL,
			0x76f988daL, 0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L,
			0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L, 0x27b70a85L,
			0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L, 0x650a7354L, 0x766a0abbL,
			0x81c2c92eL, 0x92722c85L, 0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L,
			0xc76c51a3L, 0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
			0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L, 0x391c0cb3L,
			0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L, 0x748f82eeL, 0x78a5636fL,
			0x84c87814L, 0x8cc70208L, 0x90befffaL, 0xa4506cebL, 0xbef9a3f7L,
			0xc67178f2L };

	private int[] inputs;
	private int[] outputs;
	private UniversalCircuitGenerator generator;

	public SHA256(UniversalCircuitGenerator generator, int[] inputs) {

		if (inputs.length % 16 != 0) {
			throw new IllegalArgumentException();
		}
		this.generator = generator;
		this.inputs = inputs;
		
		specifyCircuit();
	}

	public void specifyCircuit() {

		int h0 = generator.mulBinaryOp(generator.getOneIndex(),
				generator.getOneIndex());
		generator.setRuntimeSpecEntryForBinaryOp(1, BigInteger.valueOf(H[0]));

		int h1 = generator.mulBinaryOp(generator.getOneIndex(),
				generator.getOneIndex());
		generator.setRuntimeSpecEntryForBinaryOp(1, BigInteger.valueOf(H[1]));

		int h2 = generator.mulBinaryOp( generator.getOneIndex(),
				generator.getOneIndex());
		generator.setRuntimeSpecEntryForBinaryOp(1, BigInteger.valueOf(H[2]));

		int h3 = generator.mulBinaryOp( generator.getOneIndex(),
				generator.getOneIndex());
		generator.setRuntimeSpecEntryForBinaryOp(1, BigInteger.valueOf(H[3]));

		int h4 = generator.mulBinaryOp( generator.getOneIndex(),
				generator.getOneIndex());
		generator.setRuntimeSpecEntryForBinaryOp(1, BigInteger.valueOf(H[4]));

		int h5 = generator.mulBinaryOp( generator.getOneIndex(),
				generator.getOneIndex());
		generator.setRuntimeSpecEntryForBinaryOp(1, BigInteger.valueOf(H[5]));

		int h6 = generator.mulBinaryOp( generator.getOneIndex(),
				generator.getOneIndex());
		generator.setRuntimeSpecEntryForBinaryOp(1, BigInteger.valueOf(H[6]));

		int h7 = generator.mulBinaryOp( generator.getOneIndex(),
				generator.getOneIndex());
		generator.setRuntimeSpecEntryForBinaryOp(1, BigInteger.valueOf(H[7]));

		Integer[] words = new Integer[64];
		int[][] wordBits = new int[64][];
		Integer[] wordsRR7 = new Integer[64];
		Integer[] wordsRR18 = new Integer[64];
		Integer[] wordsRS3 = new Integer[64];

		Integer[] wordsRR17 = new Integer[64];
		Integer[] wordsRR19 = new Integer[64];
		Integer[] wordsRS10 = new Integer[64];

		Arrays.fill(words, null);
		Arrays.fill(wordsRR17, null);
		Arrays.fill(wordsRR18, null);
		Arrays.fill(wordsRR19, null);
		Arrays.fill(wordsRR7, null);
		Arrays.fill(wordsRS10, null);
		Arrays.fill(wordsRS3, null);

		for (int j = 0; j < inputs.length / 16; j++) {
			for (int i = 0; i < 16; i++) {
				words[i] = inputs[i + j * 16];
				int[] out = generator.split32ToBitsAndApplySet(
						words[i], 32,
						Split32OperationUtil.getRotateRightCoefficients(7));
				wordBits[i] = Arrays.copyOfRange(out, 0, 32);
				wordsRR7[i] = out[32];
				if (i >= 1) {
					out = generator.customOp3( wordBits[i], true,
							Split32OperationUtil.getRotateRightCoefficients(18),
							Split32OperationUtil.getShiftRightCoefficients(3));
					wordsRR18[i] = out[0];
					wordsRS3[i] = out[1];
				}
				if (i >= 14) {
					out = generator.customOp3( wordBits[i], true,
							Split32OperationUtil.getRotateRightCoefficients(17),
							Split32OperationUtil.getRotateRightCoefficients(19));
					wordsRR17[i] = out[0];
					wordsRR19[i] = out[1];
					out = generator.customOp3( wordBits[i], true,
							Split32OperationUtil.getShiftRightCoefficients(10),
							Split32OperationUtil.getShiftRightCoefficients(10));
					wordsRS10[i] = out[0];
				}
			}

			for (int i = 16; i < 64; i++) {

				int s0_tmp1 = generator.bitwiseOp( wordsRR7[i - 15],
						wordsRR18[i - 15], BitwiseOperationType.xor);
				int s0 = generator.bitwiseOp( s0_tmp1,
						wordsRS3[i - 15], BitwiseOperationType.xor);

				int s1_tmp1 = generator.bitwiseOp( wordsRR17[i - 2],
						wordsRR19[i - 2], BitwiseOperationType.xor);
				int s1 = generator.bitwiseOp( s1_tmp1,
						wordsRS10[i - 2], BitwiseOperationType.xor);

				generator.addBinaryOp( words[i - 16], words[i - 7]);
				int t2 = generator.customBinaryOp( s0, s1,
						OperationType.add, OperationType.add, true);

				int[] t2_splitted = generator.splitBinary( t2,
						new int[] { 32, 2 });
				words[i] = t2_splitted[0];
				// wordBits[i] = split32ToBits( words[i], 32);

				int rem = t2_splitted[1]; // range 2 bits
				int[] rem_splitted = generator.splitBinary( rem,
						new int[] { 1, 1 });
				generator.addBitToVerify(rem_splitted[0]);
				generator.addBitToVerify(rem_splitted[1]);

				int[] out = generator.split32ToBitsAndApplySet(
						words[i], 32,
						Split32OperationUtil.getRotateRightCoefficients(17));
				wordBits[i] = Arrays.copyOfRange(out, 0, 32);
				wordsRR17[i] = out[32];

				if (i < 64 - 15) {
					out = generator.customOp3( wordBits[i], true,
							Split32OperationUtil.getRotateRightCoefficients(7),
							Split32OperationUtil.getRotateRightCoefficients(18));
					wordsRR7[i] = out[0];
					wordsRR18[i] = out[1];
					out = generator.customOp3( wordBits[i], true,
							Split32OperationUtil.getShiftRightCoefficients(3),
							Split32OperationUtil.getShiftRightCoefficients(3));
					wordsRS3[i] = out[0];
				}
				if (i < 64 - 2) {
					out = generator.customOp3( wordBits[i], true,
							Split32OperationUtil.getRotateRightCoefficients(19),
							Split32OperationUtil.getShiftRightCoefficients(10));
					wordsRR19[i] = out[0];
					wordsRS10[i] = out[1];
				}
			}

			int a, b, c, d, e, f, g, h;
			a = h0;
			b = h1;
			c = h2;
			d = h3;
			e = h4;
			f = h5;
			g = h6;
			h = h7;

			int[] aBits;
			int aRR2;
			int aRR13;
			int aRR22;
			int[] out = generator.split32ToBitsAndApplySet( a, 32,
					Split32OperationUtil.getRotateRightCoefficients(2));
			aBits = Arrays.copyOfRange(out, 0, 32);
			aRR2 = out[32];
			out = generator.customOp3( aBits, true,
					Split32OperationUtil.getRotateRightCoefficients(13),
					Split32OperationUtil.getRotateRightCoefficients(22));
			aRR13 = out[0];
			aRR22 = out[1];

			int[] eBits;
			int eRR6;
			int eRR11;
			int eRR25;
			out = generator.split32ToBitsAndApplySet( e, 32,
					Split32OperationUtil.getRotateRightCoefficients(6));
			eBits = Arrays.copyOfRange(out, 0, 32);
			eRR6 = out[32];
			out = generator.customOp3( eBits, true,
					Split32OperationUtil.getRotateRightCoefficients(11),
					Split32OperationUtil.getRotateRightCoefficients(25));
			eRR11 = out[0];
			eRR25 = out[1];

			for (int i = 0; i < 64; i++) {

				int s1_tmp = generator.bitwiseOp( eRR6, eRR11,
						BitwiseOperationType.xor);
				int s1 = generator.bitwiseOp( s1_tmp, eRR25,
						BitwiseOperationType.xor);

				int s0_tmp = generator.bitwiseOp( aRR2, aRR13,
						BitwiseOperationType.xor);
				int s0 = generator.bitwiseOp( s0_tmp, aRR22,
						BitwiseOperationType.xor);

				// ch := (e and f) xor ((not e) and g)

				int ch1 = generator.bitwiseOp( e, f,
						BitwiseOperationType.and);
				int ch2 = generator.bitwiseOp( e, g,
						BitwiseOperationType.andInv1);
				int ch = generator.bitwiseOp( ch1, ch2,
						BitwiseOperationType.xor);

				// maj := (a and b) xor (a and c) xor (b and c)

				int maj1 = generator.bitwiseOp( a, b,
						BitwiseOperationType.and);
				int maj2 = generator.bitwiseOp( a, c,
						BitwiseOperationType.and);
				int maj3 = generator.bitwiseOp( b, c,
						BitwiseOperationType.and);
				int maj4 = generator.bitwiseOp( maj1, maj2,
						BitwiseOperationType.xor);
				int maj = generator.bitwiseOp( maj3, maj4,
						BitwiseOperationType.xor);
				;
				// int ch = bitwiseOp( ch1, ch2,
				// BitwiseOperationType.xor);

				// makeStmtOutput( s0);
				// makeStmtOutput( s1);
				// makeStmtOutput( ch);
				// makeStmtOutput( maj);

				// computing temp1
				generator.customBinaryOp( h, s1, OperationType.add,
						OperationType.add, false);
				generator.setRuntimeSpecEntryForBinaryOp(4,
						BigInteger.valueOf(K[i]));
				int temp1 = generator.customBinaryOp( ch, words[i],
						OperationType.add, OperationType.add, true);
				;
				int temp2 = generator.customBinaryOp( s0, maj,
						OperationType.add, OperationType.add, false);
				;

				// if (i == 32){
				// makeStmtOutput(s1);
				// makeStmtOutput(s0);
				// makeStmtOutput(ch);
				// makeStmtOutput(maj);
				// makeStmtOutput(temp1);
				// makeStmtOutput(temp2);
				// }

				h = g;
				g = f;
				f = e;

				// e = d + temp1; // UPDATE
				int tempE = generator.customBinaryOp( d, temp1,
						OperationType.add, OperationType.add, false);
				int[] tempESplitted = generator.splitBinary( tempE,
						new int[] { 32, 3 });
				e = tempESplitted[0];
				// eBits = split32ToBits( e, 32);

				int[] remaining = generator.splitBinary(
						tempESplitted[1], new int[] { 1, 2 });
				generator.addBitToVerify(remaining[0]);
				int[] remaining2 = generator.splitBinary(
						remaining[1], new int[] { 1, 1 });
				generator.addBitToVerify(remaining2[0]);
				generator.addBitToVerify(remaining2[1]);

				d = c;
				c = b;
				b = a;

				int tempA = generator.customBinaryOp( temp2, temp1,
						OperationType.add, OperationType.add, false);
				int[] tempASplitted = generator.splitBinary( tempA,
						new int[] { 32, 3 });
				a = tempASplitted[0];
				// aBits = split32ToBits( a, 32);

				remaining = generator.splitBinary( tempASplitted[1],
						new int[] { 1, 2 });
				generator.addBitToVerify(remaining[0]);
				remaining2 = generator.splitBinary( remaining[1],
						new int[] { 1, 1 });
				generator.addBitToVerify(remaining2[0]);
				generator.addBitToVerify(remaining2[1]);

				out = generator.split32ToBitsAndApplySet( a, 32,
						Split32OperationUtil.getRotateRightCoefficients(2));
				aBits = Arrays.copyOfRange(out, 0, 32);
				aRR2 = out[32];
				out = generator.customOp3( aBits, true,
						Split32OperationUtil.getRotateRightCoefficients(13),
						Split32OperationUtil.getRotateRightCoefficients(22));
				aRR13 = out[0];
				aRR22 = out[1];

				out = generator.split32ToBitsAndApplySet( e, 32,
						Split32OperationUtil.getRotateRightCoefficients(6));
				eBits = Arrays.copyOfRange(out, 0, 32);
				eRR6 = out[32];
				out = generator.customOp3( eBits, true,
						Split32OperationUtil.getRotateRightCoefficients(11),
						Split32OperationUtil.getRotateRightCoefficients(25));
				eRR11 = out[0];
				eRR25 = out[1];

			}

			a = generator.customBinaryOp( a, h0, OperationType.add,
					OperationType.add, false);
			b = generator.customBinaryOp( b, h1, OperationType.add,
					OperationType.add, false);
			c = generator.customBinaryOp( c, h2, OperationType.add,
					OperationType.add, false);
			d = generator.customBinaryOp( d, h3, OperationType.add,
					OperationType.add, false);
			e = generator.customBinaryOp( e, h4, OperationType.add,
					OperationType.add, false);
			f = generator.customBinaryOp( f, h5, OperationType.add,
					OperationType.add, false);
			g = generator.customBinaryOp( g, h6, OperationType.add,
					OperationType.add, false);
			h = generator.customBinaryOp( h, h7, OperationType.add,
					OperationType.add, false);

			h0 = trimOneBit( a);
			h1 = trimOneBit( b);
			h2 = trimOneBit( c);
			h3 = trimOneBit( d);
			h4 = trimOneBit( e);
			h5 = trimOneBit( f);
			h6 = trimOneBit( g);
			h7 = trimOneBit( h);

			// output:
			// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

		}

		outputs = new int[]{h0, h1, h2, h3, h4, h5, h6, h7};
	}

	private int trimOneBit(int index) {
		int[] tempSplitted = generator.splitBinary( index, new int[] {
				32, 1 });
		int answer = tempSplitted[0];
		generator.split32ToBits( answer, 32);
		generator.addBitToVerify(tempSplitted[1]);
		return answer;
	}

	public int[] getOutputs() {
		return outputs;
	}

}
