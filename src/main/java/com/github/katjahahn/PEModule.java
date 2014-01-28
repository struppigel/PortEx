package com.github.katjahahn;

import java.io.IOException;

/**
 * @author Katja Hahn
 *
 */
public abstract class PEModule {

	public static final String NL = System.getProperty("line.separator");
	public abstract String getInfo();
	
	public abstract void read() throws IOException;
	
}
