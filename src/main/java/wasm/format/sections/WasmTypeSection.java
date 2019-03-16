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
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmFuncType;

public class WasmTypeSection extends WasmPayload {

	private Leb128 count;
	private List<WasmFuncType> types = new ArrayList<WasmFuncType>();
	
	public WasmTypeSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			types.add(new WasmFuncType(reader));
		}
		
	}


	@Override
	public void fillPayloadStruct(Structure structure) throws DuplicateNameException, IOException {
		structure.add(count.getType(), count.getSize(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(types.get(i).toDataType(), types.get(i).toDataType().getLength(), "type_"+i, null);
		}		
	}

	@Override
	public String getName() {
		return ".type";
	}
}
