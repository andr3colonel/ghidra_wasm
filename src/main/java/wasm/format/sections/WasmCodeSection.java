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

public class WasmCodeSection extends WasmPayload {

	private int count;
	List<WasmFunctionBody> functions = new ArrayList <WasmFunctionBody>();

	private List<WasmSection> sections = new ArrayList<WasmSection>();
	
	public WasmCodeSection (BinaryReader reader) throws IOException {
		count = Leb128.read_int(reader);
		for (int i =0; i < count; ++i) {
			functions.add(new WasmFunctionBody(reader));
		}
	}
	
	public List<WasmFunctionBody> getFunctions() {
		return functions;
	}

	@Override
	public void deserializePayload(byte[] payload) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void fillPayloadStruct(Structure structure) {
		// TODO Auto-generated method stub
		
	}


}
