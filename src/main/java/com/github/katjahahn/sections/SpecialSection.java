package com.github.katjahahn.sections;

/**
 * Represents a special section, whose format is described in the PECOFF
 * 
 * @author Katja Hahn
 *
 */
public interface SpecialSection {

	/**
	 * Returns description string
	 * 
	 * @return description string
	 */
	public String getInfo();
	
	/**
	 * Returns the file offset for the section
	 * 
	 * @return file offset
	 */
	public long getOffset();
}
