package wasm.format.sections;

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
import wasm.format.sections.structures.WasmFunctionBody;

public class WasmCodeSection implements WasmPayload {

	private Leb128 count;
	List<WasmFunctionBody> functions = new ArrayList <WasmFunctionBody>();
	
	public WasmCodeSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			functions.add(new WasmFunctionBody(reader));
		}
	}
	
	public List<WasmFunctionBody> getFunctions() {
		return functions;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("CodeSection", 0);
		structure.add(count.getType(), count.getSize(), "count", null);
		int function_id = 0;
		for (WasmFunctionBody function: functions) {
			structure.add(function.toDataType(), function.toDataType().getLength(), "function_" + function_id, null);
			function_id ++;
		}
		return structure;
	}

	@Override
	public String getName() {
		return ".code";
	}


}
