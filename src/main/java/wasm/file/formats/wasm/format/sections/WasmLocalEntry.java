package wasm.file.formats.wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.file.formats.wasm.format.Leb128;

public class WasmLocalEntry implements StructConverter {

	
	public enum WasmLocalType {
		LOCAL_INT,
		LOCAL_BOOL,
		LOCAL_FLOAT
	}
	
	private int count;
	private int type;
	
	public WasmLocalEntry(BinaryReader reader) throws IOException {
		count = Leb128.read_int(reader);
		type = Leb128.read_int(reader);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}

}
