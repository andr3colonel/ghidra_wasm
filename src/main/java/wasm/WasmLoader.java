/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wasm;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import wasm.file.formats.wasm.format.Utils;
import wasm.file.formats.wasm.format.WasmConstants;
import wasm.file.formats.wasm.format.WasmHeader;
import wasm.file.formats.wasm.format.sections.WasmCodeSection;
import wasm.file.formats.wasm.format.sections.WasmFunctionBody;
import wasm.file.formats.wasm.format.sections.WasmLocalEntry.WasmLocalType;
import wasm.file.formats.wasm.format.sections.WasmSection;
import wasm.file.formats.wasm.format.sections.WasmSection.WasmSectionId;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class WasmLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "WebAssembly";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
			WasmHeader header = new WasmHeader(reader);
			if (WasmConstants.WASM_MAGIC_BASE.equals(new String(header.getMagic()))) {
				List<QueryResult> queries =
					QueryOpinionService.query(getName(), WasmConstants.MACHINE, null);
				for (QueryResult result : queries) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
		return loadSpecs;
	}
	
	
	private void createMethodByteCodeBlock(Program program, long length, TaskMonitor monitor) throws Exception {
		Address address = toAddr( program, Utils.METHOD_ADDRESS );
		MemoryBlock block = program.getMemory( ).createInitializedBlock( "method_bytecode", address, length, (byte) 0xff, monitor, false );
		block.setRead( true );
		block.setWrite( false );
		block.setExecute( true );
	}

	private void createMethodLookupMemoryBlock(Program program, TaskMonitor monitor) throws Exception {
		Address address = toAddr( program, Utils.LOOKUP_ADDRESS );
		MemoryBlock block = program.getMemory( ).createInitializedBlock( "method_lookup", address, Utils.MAX_METHOD_LENGTH, (byte) 0xff, monitor, false );
		block.setRead( true );
		block.setWrite( false );
		block.setExecute( false );
	}
	
	private Address toAddr( Program program, long offset ) {
		return program.getAddressFactory( ).getDefaultAddressSpace( ).getAddress( offset );
	}


	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
			monitor.setMessage( "Wasm Loader: Start loading" );
			
			try {
				Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress( 0x0 );
				long length = provider.length();
	
				try (InputStream inputStream = provider.getInputStream(0)) {
					program.getMemory().createInitializedBlock(".wasm", start, inputStream, length, monitor, false);
				}
				
				BinaryReader reader = new BinaryReader( provider, true );
				WasmHeader header = new WasmHeader ( reader );
	
				createMethodLookupMemoryBlock( program, monitor );
				createMethodByteCodeBlock( program, length, monitor);

				monitor.setMessage( "Wasm Loader: Create byte code" );
				
				for (WasmSection section: header.getSections()) {
					monitor.setMessage("Loaded " + section.getId().toString());
					if (section.getId() == WasmSectionId.SEC_CODE) {
						WasmCodeSection codeSection = (WasmCodeSection)section.getPayload();
						long code_offset = section.getPayloadOffset();
						int lookupOffset = 0;
						for (WasmFunctionBody method: codeSection.getFunctions()) {
							long method_offset = code_offset + method.getOffset();
							Address methodAddress = toAddr( program, Utils.METHOD_ADDRESS + method_offset );
							Address methodIndexAddress = toAddr( program, Utils.LOOKUP_ADDRESS + lookupOffset );
							byte [] instructionBytes = method.getInstructions();
							program.getMemory( ).setBytes( methodAddress, instructionBytes );
							program.getMemory( ).setInt( methodIndexAddress, (int) methodAddress.getOffset( ) );
							lookupOffset += 4;
						}
					}
				}
			} catch (Exception e) {
				log.appendException( e );
			}

		// TODO: Load the bytes from 'provider' into the 'program'.
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}
}
