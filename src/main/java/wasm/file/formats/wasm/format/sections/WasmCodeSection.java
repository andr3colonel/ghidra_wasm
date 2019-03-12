package wasm.file.formats.wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.file.formats.wasm.format.Leb128;

public class WasmCodeSection implements StructConverter {

	private int count;
	List<WasmFunctionBody> functions = new ArrayList <WasmFunctionBody>();
	
	
	public WasmCodeSection (BinaryReader reader) throws IOException {
		count = Leb128.read_int(reader);
		for (int i =0; i < count; ++i) {
			functions.add(new WasmFunctionBody(reader));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}
	
	public List<WasmFunctionBody> getFunctions() {
		return functions;
	}

}
