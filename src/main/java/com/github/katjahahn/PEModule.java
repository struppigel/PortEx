package com.github.katjahahn;

public interface PEModule {

    /**
     * Returns the file offset for the beginning of the module
     * 
     * @return file offset for the beginning of the module
     */
    public long getOffset();

    /**
     * Returns a description string of the {@link Header}.
     * 
     * @return description string
     */
    public String getInfo();
}
