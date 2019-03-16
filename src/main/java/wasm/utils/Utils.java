package wasm.utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class Utils {
	public final static long METHOD_ADDRESS = 0x1000;
	public final static long LOOKUP_ADDRESS = 0x2000;
	public final static long MAX_METHOD_LENGTH = (long) Math.pow(2, 16) * 4;
	
	public static Address toAddr( Program program, long offset ) {
		return program.getAddressFactory( ).getDefaultAddressSpace( ).getAddress( offset );
	}
}
