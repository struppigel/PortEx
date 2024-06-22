package com.github.katjahahn.parser;

import com.github.katjahahn.parser.sections.clr.CLRSection;
import com.github.katjahahn.parser.sections.debug.CodeviewInfo;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.testng.Assert.*;

public class PEDataTest {

    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void loadClrSection(){
        Optional<CLRSection> clr = pedata.get("HelloWorld.exe").loadClrSection();
        assertTrue(clr.isPresent());
        Optional<CLRSection> noclr = pedata.get("WMIX.exe").loadClrSection();
        assertFalse(noclr.isPresent());
        // test repeated loads
        clr = pedata.get("HelloWorld.exe").loadClrSection();
        assertTrue(clr.isPresent());
        noclr = pedata.get("WMIX.exe").loadClrSection();
        assertFalse(noclr.isPresent());
    }

    @Test
    public void isDotNet(){
        PEData dotnetPe = pedata.get("HelloWorld.exe");
        assertTrue(dotnetPe.isDotNet());
        PEData pe = pedata.get("WMIX.exe");
        assertFalse(pe.isDotNet());
    }

    @Test
    public void loadCodeview() {
        Optional<CodeviewInfo> codeView = pedata.get("WMIX.exe").loadCodeViewInfo();
        byte[] guid = {36, 88, 100, -120, 25, 75, 48, 66, -106, -88, -40, 71, 118, -90, -83, 110};
        assertTrue(codeView.isPresent());
        assertEquals(codeView.get().filePath(), "C:\\CodeBases\\isdev\\redist\\Language Independent\\i386\\setupPreReq.pdb");
        assertEquals(codeView.get().age(), 1L);
        assertEquals(codeView.get().guid(), guid);
    }


    @Test
    public void loadExports(){
        // some exports
        assertEquals(pedata.get("Lab17-02dll").loadExports().size(), 9);
        assertTrue(pedata.get("Lab17-02dll").hasExports());
        // no exports
        assertEquals(pedata.get("smallest-pe.exe").loadExports().size(), 0);
        assertFalse(pedata.get("smallest-pe.exe").hasExports());
    }

    @Test
    public void hasGroupIcon(){
        assertTrue(pedata.get("WMIX.exe").hasGroupIcon());
        assertFalse(pedata.get("smallest-pe.exe").hasGroupIcon());
    }

    @Test
    public void loadIcons(){
        assertEquals(pedata.get("WMIX.exe").loadIcons().size(),3);
        assertEquals(pedata.get("smallest-pe.exe").loadIcons().size(), 0);
    }

    @Test
    public void loadImportsHasImports(){
        // some imports
        assertEquals(pedata.get("WMIX.exe").loadImports().size(), 11);
        assertTrue(pedata.get("WMIX.exe").hasImports());
        // no imports
        assertEquals(pedata.get("smallest-pe.exe").loadImports().size(), 0);
        assertFalse(pedata.get("smallest-pe.exe").hasImports());
    }

    @Test
    public void loadManifests(){
        PEData wmic = pedata.get("WMIX.exe");

        assertEquals(wmic.loadManifests().size(), 2);
        assertEquals(wmic.loadManifests(1333).size(), 2);
        assertEquals(wmic.loadManifests(1332).size(), 1);
        assertEquals(wmic.loadManifests().size(), 1); // still same size
        assertEquals(wmic.loadManifests(0).size(), 0);
        assertEquals(wmic.loadManifests().size(), 0); // still same size
        assertEquals(pedata.get("smallest-pe.exe").loadManifests().size(), 0);

        assertEquals(wmic.loadManifests(1333).get(0).length(), 1333);
        assertEquals(wmic.loadManifests(1333).get(1).length(), 638);
        assertEquals(wmic.loadManifests(1332).get(0).length(), 638);
        assertEquals(wmic.loadManifests().get(0).length(), 638); // still same size

        wmic.setMaxManifestSize(1333);
        assertEquals(wmic.loadManifests().size(), 2);
        wmic.setMaxManifestSize(1332);
        assertEquals(wmic.loadManifests().size(), 1);
        wmic.setMaxManifestSize(0);
        assertEquals(wmic.loadManifests().size(), 0);
    }


    @Test
    public void loadPDBPath() {
        PEData data = pedata.get("WMIX.exe");
        String pdb = data.loadPDBPath();
        assertEquals(pdb, "C:\\CodeBases\\isdev\\redist\\Language Independent\\i386\\setupPreReq.pdb");
        assertTrue(data.loadCodeViewInfo().isPresent());
        assertEquals(pdb, data.loadCodeViewInfo().get().filePath());
    }

    @Test
    public void isReproBuild(){
        PEData data = pedata.get("NetCoreConsole.dll");
        assertNotNull(data);
        assertTrue(data.isReproBuild());
        PEData nonrepro = pedata.get("WMIX.exe");
        assertFalse(nonrepro.isReproBuild());
    }

    @Test
    public void loadResources(){
        assertEquals(pedata.get("WMIX.exe").loadResources().size(), 69);
        assertEquals(pedata.get("smallest-pe.exe").loadResources().size(), 0);
    }

    @Test
    public void loadStringTable(){
        PEData data = pedata.get("WMIX.exe");
        Map<Long, String> table = data.loadStringTable();
        Map<Long, String> compareTable = new HashMap<Long,String>() {
            {
                put(1804L, "Choose Setup Language");
                put(1812L, "Select the language for the installation from the choices below.");
                put(1813L, "&OK");
                put(1815L, "InstallShield Wizard");
                put(1822L, "Cancel");
                put(1834L, "&Next >");
                put(1835L, "< &Back");
                put(1837L, "Do you wish to install %s?");
                put(1838L, "Authenticity Verified");
                put(1840L, "Caution: %s affirms this software is safe.  You should only continue if you trust %s to make this assertion.");
                put(1841L, "&Always trust software published by %s.");
                put(1842L, "This software has not been altered since publication by %s.  To install %s, click OK.");
                put(1854L, "InstallShield");
                put(1604L, "This setup does not contain the Windows Installer engine (%s) required to run the installation on this operating system.");
                put(1607L, "Unable to install %s Scripting Runtime.");
                put(1608L, "Unable to create InstallDriver instance, Return code: %d");
                put(1609L, "Please specify a location to save the installation package.");
                put(1865L, "Preparing Setup");
                put(1866L, "Please wait while the InstallShield Wizard prepares the setup.");
                put(1611L, "Unable to extract the file %s.");
                put(1100L, "Setup Initialization Error");
                put(1612L, "Extracting files.");
                put(1101L, "%s");
                put(1613L, "Downloading file %s.");
                put(1102L, "%1 Setup is preparing the %2, which will guide you through the program setup process.  Please wait.");
                put(1614L, "An error occurred while downloading the file %s.  What would you like to do?");
                put(1104L, "Checking Windows(R) Installer Version");
                put(1616L, "min");
                put(1872L, "Finish");
                put(1105L, "Configuring Windows Installer");
                put(1617L, "sec");
                put(1873L, "Transfer rate: ");
                put(1106L, "Configuring %s");
                put(1618L, "MB");
                put(1874L, "Estimated time left:");
                put(1107L, "Setup has completed configuring the Windows Installer on your system. The system needs to be restarted in order to continue with the installation. Please click Restart to reboot the system.");
                put(1619L, "KB");
                put(1108L, "%s");
                put(1620L, "/sec");
                put(1621L, "Failed to verify signature of file %s.");
                put(1622L, "Estimated time remaining: ");
                put(1623L, "%d %s of %d %s downloaded at %01d.%01d %s%s");
                put(1624L, "Preparing to Install...");
                put(1880L, "/s");
                put(1625L, "Get help for this installation.");
                put(1626L, "Help");
                put(1627L, "Unable to save file: %s");
                put(1628L, "Failed to complete installation.");
                put(1629L, "Invalid command line.");
                put(1630L, "/UA<url to InstMsiA.exe>");
                put(1632L, "/UM<url to msi package>");
                put(1888L, "Exit Setup");
                put(2144L, "Do you want to run this setup?");
                put(1633L, "/US<url to IsScript.msi>");
                put(1889L, "Are you sure you want to cancel the setup?");
                put(1634L, "Setup Initialization Error, failed to clone the process.");
                put(2146L, "The origin and integrity of this application could not be verified.  You should continue only if you can identify the publisher as someone you trust and are certain this application hasn't been altered since publication.");
                put(1635L, "The file %s already exists.  Would you like to replace it?");
                put(2147L, "I &do not trust this setup");
                put(2148L, "I &understand the security risk and wish to continue");
                put(1125L, "Choose Setup Language");
                put(1126L, "Select the language for this installation from the choices below.");
                put(1127L, "The installer must restart your system to complete configuring the Windows Installer service.  Click Yes to restart now or No if you plan to restart later.");
                put(2151L, "The origin and integrity of this application could not be verified because it was not signed by the publisher.   You should continue only if you can identify the publisher as someone you trust and are certain this application hasn't been altered since publication.");
                put(1128L, "This setup will perform an upgrade of '%s'. Do you want to continue?");
                put(2152L, "The origin and integrity of this application could not be verified. The certificate used to sign the software has expired or is invalid or untrusted.   You should continue only if you can identify the publisher as someone you trust and are certain this application hasn't been altered since publication.");
                put(1129L, "A later version of '%s' is already installed on this machine. The setup cannot continue.");
                put(2153L, "The software is corrupted or has been altered since it was published.  You should not continue this setup.");
                put(1130L, "OK");
                put(1642L, "Could not verify signature.  You need Internet Explorer 3.02 or later with Authenticode update.");
                put(2154L, "This setup was created with a BETA VERSION of %s");
                put(1131L, "Cancel");
                put(1643L, "Setup requires a newer version of WinInet.dll.  You may need to install Internet Explorer 3.02 or later.");
                put(2155L, "This Setup was created with an EVALUATION VERSION of %s");
                put(1132L, "Password:");
                put(1644L, "You do not have sufficient privileges to complete this installation. Log on as administrator and then retry this installation");
                put(2156L, "Please enter the password");
                put(1133L, "Install");
                put(1645L, "Error installing Microsoft(R) .NET Framework, Return Code: %d");
                put(1901L, "&Install a new instance of this application.");
                put(2157L, "This setup was created with an EVALUATION VERSION of %s, which does not support extraction of the internal MSI file. The full version of InstallShield supports this functionality. For more information, see InstallShield KB article Q200900.");
                put(1134L, "&Next >");
                put(1646L, "%s optionally uses the Microsoft (R) .NET %s Framework.  Would you like to install it now?");
                put(2158L, "This setup was created with an EVALUATION VERSION of %s. Evaluation setups work for only %s days after they were built. Please rebuild the setup to run it again. The setup will now exit.");
                put(1648L, "Setup has detected an incompatible version of Windows. Please click OK and verify that the target system is running either Windows 95 (or later version), or Windows NT 4.0 Service Pack 3 (or later version), before relaunching the installation");
                put(1904L, "Select the appropriate application instance to maintain or update.");
                put(1649L, "%s optionally uses the Visual J# Redistributable Package. Would you like to install it now? ");
                put(1905L, "Setup has detected one or more instances of this application already installed on your system.");
                put(1650L, " (This will also install the .NET Framework.)");
                put(1906L, "&Maintain or update the instance of this application selected below:");
                put(1651L, "Setup has detected an incompatible version of Windows. Please click OK and verify that the target system is running Windows 2000 Service Pack 3 (or later version), before relaunching the installation");
                put(1907L, "Setup has detected one or more instances of this application already installed on your system. You can maintain or update an existing instance or install a completely new instance.");
                put(1652L, "%s requires the following items to be installed on your computer. Click Install to begin installing these requirements.");
                put(1908L, "Select the instance of the application you want to &maintain or update below:");
                put(1653L, "Installing %s");
                put(1909L, "Display Name");
                put(1654L, "Would you like to cancel the setup after %s has finished installing?");
                put(1910L, "Install Location");
                put(1655L, "The files for installation requirement %s could not be found. The installation will now stop. This is probably due to a failed, or canceled download.");
                put(1656L, "The installation of %s appears to have failed. Do you want to continue the installation?");
                put(1657L, "Succeeded");
                put(1658L, "Installing");
                put(1659L, "Pending");
                put(1660L, "Installed");
                put(1661L, "Status");
                put(1150L, "Setup has detected an incompatible version of Windows. Please click OK and verify that the target system is running either Windows 95 (or later version), or Windows NT 4.0 Service Pack 6 (or later version), before relaunching the installation");
                put(1662L, "Requirement");
                put(1152L, "Error extracting %s to the temporary location");
                put(1664L, "Extracting");
                put(1153L, "Error reading setup initialization file");
                put(1665L, "Downloading");
                put(1154L, "Installer not found in %s");
                put(1666L, "Skipped");
                put(1155L, "File %s not found");
                put(1667L, "The installation of %s has failed. Setup will now exit.");
                put(1156L, "Internal error in Windows Installer");
                put(1668L, "The installation of %s requires a reboot.  Click Yes to restart now or No if you plan to restart later.");
                put(1669L, "%1 optionally uses %2. Would you like to install it now?");
                put(1158L, "Error populating strings. Verify that all strings in Setup.ini are valid.");
                put(1671L, "Downloading file %2 of %3: %1");
                put(2194L, "InstallShield Setup Player V24");
                put(2195L, "The path to the installation contains unsupported characters. Try moving the installation to a location that does not have special characters, and then try relaunching it.");
                put(2196L, "This setup requires administrative privileges that appear to be unavailable. Would you like to try again?");
                put(1702L, "This installation lets you install multiple instances of the product. Select the instance you would like to install, and then click Next to continue:");
                put(1703L, "&Install a new instance");
                put(1704L, "&Maintain or upgrade an existing instance");
                put(1705L, "Default");
                put(1706L, "Instance ID");
                put(1707L, "Product Name");
                put(1708L, "Location");
                put(1710L, "This installation lets you patch multiple instances of the product. Select an option below to specify how you would like to apply this patch, and then click Next to continue.");
                put(1200L, "Restart");
                put(1712L, "&Patch an existing instance");
                put(1201L, "Setup needs %lu KB free disk space in %s. Please free up some space and try again");
                put(1713L, "This installation requires Windows Installer version 4.5 or newer. Setup will now exit.");
                put(1202L, "You do not have sufficient privileges to complete this installation for all users of the machine. Log on as administrator and then retry this installation");
                put(1714L, "Decompressing");
                put(1203L, "Command line parameters:");
                put(1715L, "Version");
                put(1204L, "/L language ID");
                put(1205L, "/S Hide intialization dialog.  For silent mode use: /S /v/qn");
                put(1206L, "/V parameters to MsiExec.exe");
                put(1207L, "Windows(R) Installer %s found. This is an older version of the Windows(R) Installer. Click OK to continue.");
                put(1208L, "ANSI code page for %s is not installed on the system and therefore setup cannot run in the selected language. Run the setup and select another language.");
                put(1210L, "Setup requires Windows Installer version %s or higher to install the Microsoft .NET Framework version 2.0. Please install the Windows Installer version %s or higher and try again.");
                put(2001L, "%s Setup is preparing the InstallShield Wizard, which will guide you through the rest of the setup process. Please wait.");
                put(2002L, "Error Code:");
                put(2003L, "Error Information:");
                put(2004L, "An error (%s) has occurred while running the setup.");
                put(2005L, "Please make sure you have finished any previous setup and closed other applications. If the error still occurs, please contact your vendor: %s.");
                put(2006L, "&Detail");
                put(2007L, "&Report");
                put(2008L, "There is not enough space to initialize the setup.  Please free up at least %ld KB on your %s drive before you run the setup.");
                put(2009L, "A user with administrator rights installed this application. You need to have similar privileges to modify or uninstall it.");
                put(2010L, "Another instance of this setup is already running. Please wait for the other instance to finish and then try again. ");
            }
        };
        assertEquals(compareTable, table);
    }

    @Test
    public void loadVersionInfoHasVersionInfo(){
        assertTrue(pedata.get("WMIX.exe").loadVersionInfo().isPresent());
        assertTrue(pedata.get("WMIX.exe").hasVersionInfo());
        assertFalse(pedata.get("smallest-pe.exe").loadVersionInfo().isPresent());
        assertFalse(pedata.get("smallest-pe.exe").hasVersionInfo());
    }

}
