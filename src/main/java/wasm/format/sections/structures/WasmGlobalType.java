package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmGlobalType implements StructConverter {

	byte value_type;
	byte mutability;
	
	public WasmGlobalType  (BinaryReader reader) throws IOException {
		value_type = reader.readNextByte();
		mutability = reader.readNextByte();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("global", 0);
		structure.add(BYTE, 1, "value_type", null);
		structure.add(BYTE, 1, "mutability", null);
		return structure;
	}

}
