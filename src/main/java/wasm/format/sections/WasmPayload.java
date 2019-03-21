package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

abstract public interface WasmPayload extends StructConverter {
	abstract public String getName();	


}
