package com.github.struppigel.tools.sigscanner.v2;
/*******************************************************************************
 * Copyright 2024 Karsten Hahn
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
public enum ScanLocation {
    ENTRY_POINT(new EntryPointSigScanner()),
    MSDOS_STUB(new MSDosStubSigScanner()),
    OVERLAY(new OverlaySigScanner());

    private ScanLocationScanner scanner;

    private ScanLocation(ScanLocationScanner scanner) {
        this.scanner = scanner;
    }

    public ScanLocationScanner getScanner() {
        return scanner;
    }
}
