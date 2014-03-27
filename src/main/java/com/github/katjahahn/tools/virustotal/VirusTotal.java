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
package com.github.katjahahn.tools.virustotal;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.PEModule;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;

public class VirusTotal {

	private final String apiKey;

	public VirusTotal(String apiKey) {
		this.apiKey = apiKey;
	}

	public String uploadFile(File file) {
		try {
			StringBuilder b = new StringBuilder();
			VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(apiKey);
			VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

			ScanInfo report = virusTotalRef.scanFile(file);

			b.append("MD5:" + report.getMd5() + PEModule.NL);
			b.append("Perma link:" + report.getPermalink() + PEModule.NL);
			b.append("Resource:" + report.getResource() + PEModule.NL);
			b.append("Scan Date:" + report.getScanDate() + PEModule.NL);
			b.append("Scan Id:" + report.getScanId() + PEModule.NL);
			b.append("SHA1:" + report.getSha1() + PEModule.NL);
			b.append("SHA256: " + report.getSha256() + PEModule.NL);
			b.append("Verbose Msg: " + report.getVerboseMessage() + PEModule.NL);
			b.append("Response Code: " + report.getResponseCode() + PEModule.NL);

			return b.toString();

		} catch (UnsupportedEncodingException | UnauthorizedAccessException
				| QuotaExceededException | APIKeyNotFoundException
				| FileNotFoundException e) {
			e.printStackTrace();
		}
		return null;
	}

	public String getFileScanReport(String resource) {
		try {
			StringBuilder b = new StringBuilder();
			VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(apiKey);
			VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

			FileScanReport report = virusTotalRef.getScanReport(resource);

			b.append("MD5:" + report.getMd5() + PEModule.NL);
			b.append("Perma link:" + report.getPermalink() + PEModule.NL);
			b.append("Resource:" + report.getResource() + PEModule.NL);
			b.append("Scan Date:" + report.getScanDate() + PEModule.NL);
			b.append("Scan Id:" + report.getScanId() + PEModule.NL);
			b.append("SHA1:" + report.getSha1() + PEModule.NL);
			b.append("SHA256: " + report.getSha256() + PEModule.NL);
			b.append("Verbose Msg: " + report.getVerboseMessage() + PEModule.NL);
			b.append("Response Code: " + report.getResponseCode() + PEModule.NL);
			b.append("Positives: " + report.getPositives() + PEModule.NL);
			b.append("Total: " + report.getTotal() + PEModule.NL + PEModule.NL);

			Map<String, VirusScanInfo> scans = report.getScans();
			if (scans == null)
				return b.toString();
			for (Entry<String, VirusScanInfo> entry : scans.entrySet()) {
				VirusScanInfo virusInfo = entry.getValue();
				b.append("Scanner : " + entry.getKey() + PEModule.NL);
				b.append("Result : " + virusInfo.getResult() + PEModule.NL);
				b.append("Update : " + virusInfo.getUpdate() + PEModule.NL);
				b.append("Version :" + virusInfo.getVersion() + PEModule.NL
						+ PEModule.NL);
			}
			return b.toString();
		} catch (UnsupportedEncodingException | UnauthorizedAccessException
				| QuotaExceededException | APIKeyNotFoundException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static void main(String... args) throws IOException {
		List<String> list = Files.readAllLines(new File("vtapikey").toPath(),
				Charset.defaultCharset());
		String resource = "588092c771d1aca1784ebd58c869e0448d2d5a6f9eec266ae8dfa057e6605804";
		String report = new VirusTotal(list.get(0)).getFileScanReport(resource);
		System.out.println(report);
		// File file = new File("joined.exe");
		// System.out.println(new VirusTotal(list.get(0)).uploadFile(file));
	}
}
