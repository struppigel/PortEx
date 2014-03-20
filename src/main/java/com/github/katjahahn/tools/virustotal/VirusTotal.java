package com.github.katjahahn.tools.virustotal;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

import com.github.katjahahn.PEModule;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;

public class VirusTotal {
	
	public static void main(String... args) throws IOException {
		List<String> list = Files.readAllLines(new File("vtapikey").toPath(), Charset.defaultCharset());
		String resource = "a33c3533f22300da984fd9adc4b1a4fe58ed1f62fc0894919657e01ec70464ce";
		String report = new VirusTotal(list.get(0)).getFileScanReport(resource);
		System.out.println(report);
	}
	
	public VirusTotal(String apiKey) {
		VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(apiKey);
	}
	
	public String getFileScanReport(String resource) {
        try {
        	StringBuilder b = new StringBuilder();
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            FileScanReport report = virusTotalRef.getScanReport(resource);

            b.append("MD5:" + report.getMd5() + PEModule.NL);
            b.append("Perma link:" + report.getPermalink() + PEModule.NL);
            b.append("Resourve:" + report.getResource() + PEModule.NL);
            b.append("Scan Date:" + report.getScanDate() + PEModule.NL);
            b.append("Scan Id:" + report.getScanId() + PEModule.NL);
            b.append("SHA1:" + report.getSha1() + PEModule.NL);
            b.append("SHA256: " + report.getSha256() + PEModule.NL);
            b.append("Verbose Msg: " + report.getVerboseMessage() + PEModule.NL);
            b.append("Response Code: " + report.getResponseCode() + PEModule.NL);
            b.append("Positives: " + report.getPositives() + PEModule.NL);
            b.append("Total: " + report.getTotal() + PEModule.NL + PEModule.NL);

            Map<String, VirusScanInfo> scans = report.getScans();
            for (String key : scans.keySet()) {
                VirusScanInfo virusInfo = scans.get(key);
                b.append("Scanner : " + key + PEModule.NL);
                b.append("Result : " + virusInfo.getResult() + PEModule.NL);
                b.append("Update : " + virusInfo.getUpdate() + PEModule.NL);
                b.append("Version :" + virusInfo.getVersion() + PEModule.NL + PEModule.NL);
            }
            return b.toString();

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
		return null;
    }

}
