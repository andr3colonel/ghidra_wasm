package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;

public class WasmFuncType implements StructConverter {

	byte form;
	Leb128 param_count;
	byte[] param_types;
	Leb128 return_count;
	byte[] return_types;
	
	public WasmFuncType (BinaryReader reader) throws IOException {
		form = reader.readNextByte();
		param_count = new Leb128(reader);
		if (param_count.getValue() > 0) {
			param_types = reader.readNextByteArray(param_count.getValue());			
		}
		return_count = new Leb128(reader);
		if (return_count.getValue() > 0) {
			return_types = reader.readNextByteArray(return_count.getValue());			
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("funct_type", 0);
		structure.add(BYTE, 1, "form", null);
		structure.add(param_count.toDataType(), param_count.toDataType().getLength(), "param_count", null);
		if (param_count.getValue() > 0) {
			structure.add(new ArrayDataType(BYTE, param_count.getValue(), 1), "param_types", null);
		}
		structure.add(return_count.toDataType(), return_count.toDataType().getLength(), "return_count", null);
		if (return_count.getValue() > 0) {
			structure.add(new ArrayDataType(BYTE, return_count.getValue(), 1), "return_types", null);
		}
		return structure;
	}

}
