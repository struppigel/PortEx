/*******************************************************************************
 * Copyright 2024 Karsten Phillip Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package io.github.struppigel.tools.rehints;

public enum ReHintType {
    /**************************** RE Hints ******************************/

    /**
     * Often involves multiple structures in the PE file, purpose is to deliver
     * reverse engineering hints based on the occurance of anomalies.
     */

    AHK_RE_HINT("The executable is an AutoHotKey wrapper. Extract the resource and check the script."),

    ARCHIVE_RE_HINT("This file has an embedded archive, extract the contents with an unarchiver"),

    AUTOIT_RE_HINT("The file is an AutoIt script executable, use AutoIt-Ripper to unpack the script"),

    COMPRESSOR_PACKER_RE_HINT("This file has been packed by a simple compressor, step over the next pushad, set hardware breakpoint on ESP address on access, run until the breakpoint, then find a jump that hops the section. That is the OEP."),

    DOT_NET_CORE_APP_BUNDLE_HINT("The file is a .NET Core App Bundle, it carries the whole .NET Core execution environment in the overlay. Use ILSpy to extract files. The main code is in a DLL"),

    ELECTRON_PACKAGE_RE_HINT("This is an Electron Package executable. Look for *.asar archive in resources folder. This might be a separate file."),

    EMBEDDED_EXE_RE_HINT("This file contains an embedded executable, extract and analyse it"),

    FAKE_VMP_RE_HINT("This might be protected with an older version of VMProtect, but many have fake VMProtect section names. So check if this is really the case."),

    INNO_SETUP_RE_HINT("This file is an Inno Setup Installer, use innounp -x -m to extract files and InnoSetup Decompiler for the CompiledCode.bin"),

    INSTALLER_RE_HINT("This file is an installer, extract the install script and contained files, try 7zip or run the file and look into TEMP"),

    NATIVE_DOT_NET_UNPACKING_RE_HINT("This sample might unpack managed code (.NET). Dump the assembly with MegaDumper."),

    NULLSOFT_RE_HINT("This file is a Nullsoft installer, download 7zip v15.02 to extract the install script and contained files"),

    PROCESS_DOPPELGAENGING_INJECTION_HINT("The sample has imports which can be abused for Process Doppelgänging"),

    PYINSTALLER_RE_HINT("This file is a PyInstaller executable. Use pyinstxtractor to extract the python bytecode, then apply a decompiler to the main .pyc"),

    SCRIPT_TO_EXE_WRAPPED_RE_HINT("This might be a Script-to-Exe wrapped file, check the resources for a compressed or plain script."),

    SFX_RE_HINT("This file is a self-extracting-archive. Try to extract the files with 7zip or run the file and collect them from TEMP"),

    SFX_7ZIP_OLEG_RE_HINT("This file is a modified 7zip module created by Oleg N. Scherbakov. It is either the module itself or a self-extracting archive. Try to extract contained files with 7zip or run the file and collect them from TEMP. Check for an install script starting at marker ;!@Install@!UTF-8!"),

    THREAD_NAME_CALLING_INJECTION_HINT("The sample has imports which can be abused for Thread Name-Calling injection. Check if ETHREAD->ThreadName contains shellcode"),

    UPX_PACKER_RE_HINT("This file seems to be packed with UPX, unpack it with upx.exe -d <sample>");

    private final String description;

    ReHintType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
