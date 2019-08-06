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


import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import wasm.file.WasmModule;
import wasm.format.Utils;
import wasm.format.WasmHeader;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.structures.WasmFunctionBody;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class WasmAnalyzer extends AbstractAnalyzer {

	private final static String NAME = "WebAssembly";
	private static final String DESCRIPTION =
			"WebAssembly analyzer";

	public WasmAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// TODO: Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}
	
	private Symbol createMethodSymbol(Program program, Address methodAddress, String methodName,
			Namespace classNameSpace, MessageLog log) {
		program.getSymbolTable().addExternalEntryPoint(methodAddress);
		try {
			return program.getSymbolTable().createLabel(methodAddress, methodName, classNameSpace,
				SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			log.appendException(e);
			return null;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ByteProvider provider = new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		BinaryReader reader = new BinaryReader(provider, true);
		try {
			WasmModule header = new WasmModule(reader);
			for (WasmSection section: header.getSections()) {

				// Add function into symbol tree
				if (section.getId() == WasmSectionId.SEC_CODE) {
					WasmCodeSection codeSection = (WasmCodeSection)section.getPayload();
					long code_offset = section.getPayloadOffset();
					for (WasmFunctionBody method: codeSection.getFunctions()) {
						long method_offset = code_offset + method.getOffset();
						Address methodAddress = Utils.toAddr( program, Utils.METHOD_ADDRESS + method_offset );
						createMethodSymbol(program, methodAddress, "R", null, log);
					}
				}
				else if (section.getId() == WasmSectionId.SEC_EXPORT) {
					// TODO create export symbol
					System.out.println( "WasmSectionId.SEC_EXPORT");
				}
				else if (section.getId() == WasmSectionId.SEC_IMPORT) {
					// TODO create import symbol
					System.out.println( "WasmSectionId.SEC_IMPORT");
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		return false;
	}
}
