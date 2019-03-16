package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.sections.structures.WasmFuncType;

public class WasmFunctionSection extends WasmPayload {

	private Leb128 count;
	private List<Leb128> types = new ArrayList<Leb128>();
	
	public WasmFunctionSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			types.add(new Leb128(reader));
		}		
	}


	@Override
	public void fillPayloadStruct(Structure structure) {
		structure.add(count.getType(), count.getSize(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(types.get(i).getType(), types.get(i).getSize(), "function_"+i, null);
		}				
	}

	@Override
	public String getName() {
		return ".function";
	}

}
