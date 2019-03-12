package wasm.file.formats.wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmGlobalSection implements StructConverter {

	
	public WasmGlobalSection (BinaryReader reader) throws IOException {
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}

}
