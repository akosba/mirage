/*******************************************************************************
 * Author: Ahmed Kosba <ahmed.kosba@alexu.edu.eg>
 *******************************************************************************/

package universal.opcodes.opcode3;

import java.math.BigInteger;
import java.util.Arrays;

import jsnark.util.BigIntStorage;

public class Split32OperationUtil {
	public static BigInteger[] getSplitCoefficients(){
		BigInteger[] list = new BigInteger[32];
		for(int  i =0; i < 32; i++){
			list[i] = BigIntStorage.getInstance().getBigInteger(BigInteger.ONE.shiftLeft(i)); 
		}
		return list;
	}

	public static BigInteger[] getRotateLeftCoefficients(int r){
		BigInteger[] m = getSplitCoefficients();
		BigInteger[] list = new BigInteger[32];
		for(int  i =0; i < 32; i++){
			list[i] = m[(i+r)%32]; 

		}
		return list;
	}
	
	public static BigInteger[] getRotateRightCoefficients(int r){
		BigInteger[] m = getSplitCoefficients();
		BigInteger[] list = new BigInteger[32];
		for(int  i =0; i < 32; i++){
			list[i] = m[(i-r+32)%32]; 

		}

		return list;
	}

	
	public static BigInteger[] getShiftLeftCoefficients(int s){
		BigInteger[] m = getSplitCoefficients();
		BigInteger[] list = new BigInteger[32];
		Arrays.fill(list, BigInteger.ZERO);
		for(int  i =0; i < 32; i++){
			if(i+s < 32)
				list[i] = m[(i+s)%32]; 
		}
		return list;
	}
	
	public static BigInteger[] getShiftRightCoefficients(int s){
		BigInteger[] m = getSplitCoefficients();
		BigInteger[] list = new BigInteger[32];
		Arrays.fill(list, BigInteger.ZERO);
		for(int  i =0; i < 32; i++){
			if(i-s >=0){
				list[i] = m[i-s];
			}
		}
		return list;
	}

}
