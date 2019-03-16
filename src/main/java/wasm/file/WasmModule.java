package wasm.file;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.WasmConstants;
import wasm.format.WasmHeader;
import wasm.format.sections.WasmSection;

public class WasmModule  {
	
	private WasmHeader header;
	private List<WasmSection> sections = new ArrayList<WasmSection>();
	
	public WasmModule(BinaryReader reader) throws IOException {
		header = new WasmHeader(reader);
		while (reader.getPointerIndex() < reader.length()) {
			sections.add(new WasmSection(reader));
		}
	}

	
	public WasmHeader getHeader() {
		return header;
	}
	
	public List<WasmSection> getSections() {
		return sections;
	}
}
