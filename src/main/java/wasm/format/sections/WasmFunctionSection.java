package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;

public class WasmFunctionSection extends WasmPayload {

	
	public WasmFunctionSection (BinaryReader reader) throws IOException {
	}

	@Override
	public void deserializePayload(byte[] payload) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void fillPayloadStruct(Structure structure) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String getName() {
		return ".function";
	}

}
