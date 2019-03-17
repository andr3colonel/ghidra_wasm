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
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmTableType;

public class WasmTableSection implements WasmPayload {

	private Leb128 count;
	private List<WasmTableType> types = new ArrayList<WasmTableType>();
	
	public WasmTableSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			types.add(new WasmTableType(reader));
		}	
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("TableSection", 0);
		structure.add(count.getType(), count.getSize(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(types.get(i).toDataType(), types.get(i).toDataType().getLength(), "table_type_"+i, null);
		}
		return structure;
	}


	@Override
	public String getName() {
		return ".table";
	}

}
