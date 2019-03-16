package wasm.format.sections;

import java.io.IOException;

import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;

abstract public class WasmPayload {
	abstract public void deserializePayload(byte[] payload);
	abstract public void fillPayloadStruct(Structure structure) throws DuplicateNameException, IOException;
	abstract public String getName();	
}
