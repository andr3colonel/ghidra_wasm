package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;

public class WasmLinearMemorySection extends WasmPayload {

	
	public WasmLinearMemorySection (BinaryReader reader) throws IOException {
	}


	@Override
	public void fillPayloadStruct(Structure structure) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String getName() {
		return ".linearMemory";
	}

}
