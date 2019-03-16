package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmStartSection  implements WasmPayload {

	public WasmStartSection (BinaryReader reader) throws IOException {
	}

	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("StartSection", 0);
		return structure;
	}

	@Override
	public String getName() {
		return ".start";
	}
}
