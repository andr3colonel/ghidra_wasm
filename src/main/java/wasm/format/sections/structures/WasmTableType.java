package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;

public class WasmTableType implements StructConverter {

	byte element_type;
	WasmResizableLimits limits;
	
	public WasmTableType  (BinaryReader reader) throws IOException {
		element_type = reader.readNextByte();
		limits = new WasmResizableLimits(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("table_type", 0);
		structure.add(BYTE, 1, "element_type", null);
		structure.add(limits.toDataType(), limits.toDataType().getLength(), "limits", null);
		return structure;
	}

}
