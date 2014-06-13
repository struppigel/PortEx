/*******************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.katjahahn.parser;

import java.io.IOException;

/**
 * Is thrown if a specification file doesn't have the expected formatting,
 * for example wrong delimiters.
 * 
 * @author Katja Hahn
 * 
 */
public class FileFormatException extends IOException {

	private static final long serialVersionUID = 1L;

	/**
	 * Creates a FileFormatException instance with the message.
	 * 
	 * @param message
	 */
	public FileFormatException(String message) {
		super(message);
	}

}
