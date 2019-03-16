package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;

public class WasmLocalEntry implements StructConverter {

	
	public enum WasmLocalType {
		LOCAL_INT,
		LOCAL_BOOL,
		LOCAL_FLOAT
	}
	
	private Leb128 count;
	private Leb128 type;
	
	public WasmLocalEntry(BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		type = new Leb128(reader);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("function_body", 0);
		structure.add(count.getType(), count.getSize(), "body_size", null);
		structure.add(type.getType(), type.getSize(), "local_count", null);
		return structure;
	}

}
