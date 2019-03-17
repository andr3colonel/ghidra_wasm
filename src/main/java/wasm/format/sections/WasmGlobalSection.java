package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmGlobalSection implements WasmPayload {

	
	public WasmGlobalSection (BinaryReader reader) throws IOException {
	}


	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("GlobalSection", 0);
		return structure;
		
	}

	@Override
	public String getName() {
		return ".global";
	}


}
