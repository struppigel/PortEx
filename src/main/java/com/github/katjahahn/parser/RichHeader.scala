/** *****************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * **************************************************************************** */
package com.github.katjahahn.parser

import com.github.katjahahn.parser.RichHeader.{buildMap, knownXORKeys, prodIdMap}

import scala.collection.JavaConverters._
import com.github.katjahahn.parser.msdos.MSDOSHeader
import com.google.common.primitives.Bytes
import org.apache.logging.log4j.{LogManager, Logger}

import java.math.BigInteger
import java.util.Optional

/**
 * Reads the Rich Header if it exists
 *
 * @author Karsten Philipp Boris Hahn
 *
 */
class RichHeader( private  val decodedRich : Array[Byte], private val xorKey : Array[Byte], private val actualChecksum : Array[Byte]) {

  case class RichEntry(build: Int, prodId : Int, count : Int) {
    def getProductIdStr : String = prodIdMap.getOrElse(prodId, "0x" + prodId.toHexString)
    def getBuildStr : String = buildMap.getOrElse(build, "0x" + build.toHexString)

    override def toString() : String =
      "ProdId: " + getProductIdStr + " (0x"+prodId.toHexString+"), Build: "+getBuildStr+" (0x" + build.toHexString + "), count: " + count
  }

  private val logger = LogManager.getLogger(classOf[RichHeader].getName)

  /**
   * Returns the decoded Rich header starting and including 'DanS', but excluding 'Rich'
   *
   * @return byte array of the decoded Rich header
   */
  def getDecodedRichHeaderBytes: Array[Byte] = decodedRich.clone()

  /**
   * Returns the decoded rich header without the count data. Implementation for RichPV hash according to
   * https://github.com/modubyk/PE_Richness/blob/master/parseRich.py
   * https://www.giac.org/paper/grem/6321/leveraging-pe-rich-header-static-alware-etection-linking/169729
   *
   * @return array of rich header bytes without the count data
   */
  def getDecodedRichHeaderBytesWithoutCount: Array[Byte] = {
    // the first 12 bytes are ignored because they are padding
    // apart from the padding group into 4 bytes each, then remove every second group
    // afterwards create a flat array of bytes again (the grouping made a list of arrays)
    (decodedRich.grouped(4).toList.zipWithIndex collect { case (b , i) if (i > 3) && (i % 2 == 0) => b}).flatten.toArray
  }

  /**
   * Some PE types, compilers or formats emit specific XORkeys, this returns a list of all PE types associated with
   * the XOR key used in this Rich Header
   *
   * @return List of descriptions for PE types, compilers, formats that are known to emit the Rich Header's XOR key
   */
  def getKnownFormats(): java.util.List[String] = {
    knownXORKeys.filter(_._2.contains(xorKey)).map(_._1).toList.asJava
  }

  /**
   * Parse and compose list of all entries in the decoded Rich header
   *
   * @return list of all Rich entries
   */
  def getRichEntries(): java.util.List[RichEntry] = richEntries.asJava

  private def richEntries(): List[RichEntry] = {
    val wordLen = 4
    // skip DanS and padding bytes, we start by slicing into blocks of 4 bytes already removing DanS as first block
    val dataBlocks = for(i <- wordLen until decodedRich.length by wordLen) yield decodedRich.slice(i, i + wordLen)
    // remove padding of 0 byte words TODO adjust to 16 byte alignment
    val paddingRemoved = dataBlocks.dropWhile(_.sameElements(Array[Byte](0,0,0,0)))
    logger.debug("Removed padding and DanS size " + (decodedRich.length - (paddingRemoved.length * 4)))
    // each entry is 8 bytes, where the first 2 bytes are the pid, the next 2 bytes the pv and the last 4 bytes the pc
    // note that paddingRemoved consists of blocks with 4 bytes, whereas one entry is 8 bytes
    val result = for(i <- paddingRemoved.indices by 2) yield
      RichEntry(
        build = ByteArrayUtil.bytesToInt(paddingRemoved(i).slice(0, 2)), // bytes 0-1 == Pid
        prodId = ByteArrayUtil.bytesToInt(paddingRemoved(i).slice(2, 4)),  // bytes 2-3 == Pv
        count = ByteArrayUtil.bytesToInt(paddingRemoved(i + 1))           // bytes 4-7 == Pc
      )
    result.toList
  }

  /**
   * The XOR key that is saved in the Rich Header
   * @return xor key as byte array
   */
  def getXORKey() : Array[Byte] = xorKey

  /**
   * Checks if computed checksum and XOR key are the same
   *
   * @return true iff computed checksum equals XOR key saved in Rich Header
   */
  def isValidChecksum() : Boolean = xorKey.deep == actualChecksum.deep


  def getInfo : String = richEntries().mkString(IOUtil.NL)
}

object RichHeader {

  private val logger = LogManager.getLogger(classOf[RichHeader].getName)

  val richMagic : Array[Byte] = "Rich".getBytes
  val danSMagic : Array[Byte] = "DanS".getBytes
  // based on https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/
  val knownXORKeys = Map(
    "Visual Basic 6.0" -> List(0x886973F3, 0x8869808D, 0x88AA42CF, 0x88AA2A9D, 0x89A99A19, 0x88CECC0B, 0x8897EBCB,
        0xAC72CCFA, 0x1AAAA993, 0xD05FECFB, 0x183A2CFD, 0xACCF9994, 0xC757AD0B, 0xA7EEAD02, 0xD1197995, 0x83CDAD4,
        0x8917A389, 0x88CEA841, 0x8917DE83, 0x89AA0373, 0x8ACD8739, 0x8D156179, 0x8ACE4D53, 0x8897FE31, 0x91A515F9,
        0xD1983193, 0x8D16E113, 0x9AC47EF9, 0x91A80893, 0xAD0350F9, 0xD180F4F9, 0xAD0EF593, 0x9ACA5793, 0x9ACA5793),
    "NSIS" -> List(0xD28650E9, 0x38BF1A05, 0x6A2AD175, 0xD246D0E9, 0x371742A2, 0xAB930178, 0x69EAD975, 0x69EB1175,
        0xFB2414A1, 0xFB240DA1),
    "MASM 6.14 build 8444" -> List(0x88737619, 0x89A56EF9),
    "WinRar SFX" -> List(0xC47CACAA, 0xFDAFBB1F, 0xD3254748, 0x557B8C97, 0x8DEFA739, 0x723F06DE, 0x16614BC7),
    "Autoit" -> List(0xBEAFE369, 0xC1FC1252, 0xCDA605B9, 0xA9CBC717, 0x8FEDAD28, 0x273B0B7D, 0xECFA7F86),
    "Microsoft Cabinet File" -> List(0x43FACBB6),
    "NTkernelPacker" -> List(0x377824C3),
    "Thinstall" -> List(0x8B6DF331),
    "MoleBox Ultra v4" -> List(0x8CABE24D)
  )

  private val wordLen = 4

  def apply(bytesUntilPE: Array[Byte]) : RichHeader = {
    val richOffset = Bytes.indexOf(bytesUntilPE, richMagic)
    if(richOffset == -1) throw new FileFormatException("No Rich Header found")
    if(bytesUntilPE.length < richOffset + 8) throw new FileFormatException("Rich Header malformed or truncated")
    val xorKey = bytesUntilPE.slice(richOffset + 4, richOffset + 8)
    // decode rich header backwards
    val decodedRich = decodeRichHeader(bytesUntilPE, richOffset, xorKey)
    val danSOffset = findDanSOffset(bytesUntilPE, richOffset, xorKey)
    val checksum = calculateChecksum(bytesUntilPE, danSOffset, decodedRich)
    val checksumBytes = BigInteger.valueOf(checksum).toByteArray.reverse // endianness

    new RichHeader(decodedRich, xorKey, checksumBytes)
  }

  private def calculateDosChecksum(bytesUntilPEMagic: Array[Byte], danSOffset: Int) : Int = {
    val elfanew = 0x3c
    val elfanewLength = 4
    var checksum = danSOffset
    for (i <- 0 until danSOffset) {
      if(!(elfanew <= i && i < elfanew + elfanewLength)) { //skip e_flanew
        val temp = bytesUntilPEMagic(i) & 0xff
        checksum += ((temp << (i % 32)) | (temp >> (32 - (i % 32))) & 0xff) //ROL
        checksum &= 0xffffffff
      }
    }
    checksum
  }

  private def calculateRichChecksum(decodedRich: Array[Byte]) : Int = {
    var checksum = 0
    // skip DanS and padding bytes, we start by slicing into blocks of 4 bytes already removing DanS as first block
    val dataBlocks = for (i <- wordLen until decodedRich.length by wordLen) yield decodedRich.slice(i, i + wordLen)
    // remove padding of 0 byte words TODO adjust to 16 byte alignment
    val dbNoPad = dataBlocks.dropWhile(_.sameElements(Array[Byte](0, 0, 0, 0)))
    val compids = for (i <- dbNoPad.indices by 2) yield
      (ByteArrayUtil.bytesToInt(dbNoPad(i).slice(0, 4)), // bytes 0-3 compid
        ByteArrayUtil.bytesToInt(dbNoPad(i + 1))) // bytes 4-7 count
    for ((compid, count) <- compids) {
      //println("compid: 0x" + compid.toHexString + " count: " + count)
      checksum += (compid << count % 32 | compid >> (32 - (count % 32)))
      checksum &= 0xffffffff
     // println("checksum temp: 0x" + checksum.toHexString)
    }
    checksum
  }

  private def calculateChecksum(bytesUntilPEMagic: Array[Byte], danSOffset: Int, decodedRich: Array[Byte]) =
    calculateDosChecksum(bytesUntilPEMagic, danSOffset) + calculateRichChecksum(decodedRich)

  private def findDanSOffset(bytes: Array[Byte], richOffset: Int, xorKey: Array[Byte]) : Int = {
    var danSOffset = -1
    for (i <- richOffset - richMagic.length to 0 by -wordLen) {
      val encodedDword : Array[Byte] = bytes.slice(i, i + wordLen)
      val decodedDword = for(j <- 0 until wordLen) yield (encodedDword(j) ^ xorKey(j)).toByte
      if (decodedDword.sameElements(danSMagic)) danSOffset = i
    }
    // no DanS found
    if(danSOffset == -1) throw new FileFormatException("Rich header malformed, no DanS found")
    danSOffset
  }

  private def decodeRichHeader(bytes: Array[Byte], richOffset: Int, xorKey: Array[Byte]) : Array[Byte] = {
    val danSOffset = findDanSOffset(bytes, richOffset, xorKey)
    // construct decoded header bytes, currently doesn't include "Rich"
    val encoded = bytes.slice(danSOffset, richOffset)
    // only decode until "Rich"
    val decoded = for (i <- encoded.indices) yield (encoded(i) ^ xorKey(i % wordLen)).toByte

    decoded.toArray
  }

  def newInstance(headerbytes : Array[Byte]) : RichHeader = apply(headerbytes)

  /**
   * https://github.com/dishather/richprint
   */
  val buildMap = Map(
    0x7a64 -> "VS2022 v17.2.5 build 31332",
    0x7a61 -> "VS2022 v17.2.1 build 31329",
    0x7b8d -> "VS2022 v17.3.0 pre 5.0 build 31629",
    0x7b8c -> "VS2022 v17.3.0 pre 4.0 build 31628",
    0x7b8b -> "VS2022 v17.3.0 pre 3.0 build 31627",
    0x7b1d -> "VS2022 v17.3.0 pre 2.0 build 31517",
    0x7ac0 -> "VS2022 v17.3.0 pre 1.0 build 31424",
    0x7a60 -> "VS2022 v17.2.0 build 31328",
    0x7a5e -> "VS2022 v17.2.0 pre 3.0 build 31326",
    0x7a46 -> "VS2022 v17.2.0 pre 2.1 build 31302",
    0x798a -> "VS2022 v17.2.0 pre 1.0 build 31114",
    0x7980 -> "VS2022 v17.1.0 pre 5.0 build 31104",
    0x797f -> "VS2022 v17.1.0 pre 3.0 build 31103",
    0x78c7 -> "VS2022 v17.1.0 pre 2.0 build 30919",
    0x7862 -> "VS2022 v17.1.0 pre 1.0 build 30818",
    0x77f1 -> "VS2022 v17.0.0 pre 7.0 build 30705",
    0x77f0 -> "VS2022 v17.0.0 pre 5.0 build 30704",
    0x7740 -> "VS2022 v17.0.0 pre 4.0 build 30528",
    0x76d7 -> "VS2022 v17.0.0 pre 3.1 build 30423",
    0x76c1 -> "VS2022 v17.0.0 preview2 build 30401",
    0x75c2 -> "VS2019 v16.11.17 build 30146",
    0x75c1 -> "VS2019 v16.11.15 build 30145",
    0x75c0 -> "VS2019 v16.11.14 build 30144",
    0x75bf -> "VS2019 v16.11.13 build 30143",
    0x75be -> "VS2019 v16.11.12 build 30142",
    0x75bd -> "VS2019 v16.11.11 build 30141",
    0x75bc -> "VS2019 v16.11.10 build 30140",
    0x75bb -> "VS2019 v16.11.9 build 30139",
    0x75ba -> "VS2019 v16.11.8 build 30138",
    0x75b9 -> "VS2019 v16.11.6 build 30137",
    0x75b8 -> "VS2019 v16.11.5 build 30136",
    0x75b5 -> "VS2019 v16.11.1 build 30133",
    0x7558 -> "VS2019 v16.10.4 build 30040",
    0x7556 -> "VS2019 v16.10.3 build 30038",
    0x7555 -> "VS2019 v16.10.0 build 30037",
    0x74db -> "VS2019 v16.9.5 build 29915",
    0x74da -> "VS2019 v16.9.4 build 29914",
    0x74d9 -> "VS2019 v16.9.2 build 29913",
    0x74d6 -> "VS2019 v16.9.0 build 29910",
    0x7299 -> "VS2019 v16.8.5 build 29337",
    0x7298 -> "VS2019 v16.8.4 build 29336",
    0x7297 -> "VS2019 v16.8.3 build 29335",
    0x7296 -> "VS2019 v16.8.2 build 29334",
    0x7295 -> "VS2019 v16.8.0 build 29333",
    0x71b8 -> "VS2019 v16.7.5 build 29112",
    0x71b7 -> "VS2019 v16.7.1 build 29111",
    0x71b6 -> "VS2019 v16.7.0 build 29110",
    0x7086 -> "VS2019 v16.6.2 build 28806",
    0x7085 -> "VS2019 v16.6.0 build 28805",
    0x6fc6 -> "VS2019 v16.5.5 build 28614",
    0x6fc4 -> "VS2019 v16.5.2 build 28612",
    0x6fc3 -> "VS2019 v16.5.1 build 28611",
    0x6fc2 -> "VS2019 v16.5.0 build 28610",
    0x6e9f -> "VS2019 v16.4.6 build 28319",
    0x6e9c -> "VS2019 v16.4.4 build 28316",
    0x6e9b -> "VS2019 v16.4.3 build 28315",
    0x6e9a -> "VS2019 v16.4.0 build 28314",
    0x6dc9 -> "VS2019 v16.3.2 build 28105",
    0x6d01 -> "VS2019 v16.2.3 build 27905",
    0x6c36 -> "VS2019 v16.1.2 build 27702",
    0x6b74 -> "VS2019 v16.0.0 build 27508",
    0x6996 -> "VS2017 v15.9.11 build 27030",
    0x6993 -> "VS2017 v15.9.7 build 27027",
    0x6992 -> "VS2017 v15.9.5 build 27026",
    0x6991 -> "VS2017 v15.9.4 build 27025",
    0x698f -> "VS2017 v15.9.1 build 27023",
    0x686c -> "VS2017 v15.8.5 build 26732",
    0x686a -> "VS2017 v15.8.9? build 26730",
    0x6869 -> "VS2017 v15.8.4 build 26729",
    0x6866 -> "VS2017 v15.8.0 build 26726",
    0x6741 -> "VS2017 v15.7.5 build 26433",
    0x673f -> "VS2017 v15.7.4 build 26431",
    0x673e -> "VS2017 v15.7.3 build 26430",
    0x673d -> "VS2017 v15.7.2 build 26429",
    0x673c -> "VS2017 v15.7.1 build 26428",
    0x6614 -> "VS2017 v15.6.7 build 26132",
    0x6613 -> "VS2017 v15.6.6 build 26131",
    0x6611 -> "VS2017 v15.6.3 build 26129",
    0x6610 -> "VS2017 v15.6.0 build 26128",
    0x64eb -> "VS2017 v15.5.6 build 25835",
    0x64ea -> "VS2017 v15.5.4 build 25834",
    0x64e7 -> "VS2017 v15.5.2 build 25831",
    0x63cb -> "VS2017 v15.4.5 build 25547",
    0x63c6 -> "VS2017 v15.4.4 build 25542",
    0x63a3 -> "VS2017 v15.3.3 build 25507",
    0x63a2 -> "VS2017 v15.3 build 25506",
    0x61b9 -> "VS2017 v15.0 build 25017",
    0x5e97 -> "VS2015 UPD3.1 build 24215",
    0x5e95 -> "VS2015 UPD3 build 24213",
    0x5e92 -> "VS2015 Update 3 [14.0] build 24210",
    0x5d6e -> "VS2015 UPD2 build 23918",
    0x5bd2 -> "VS2015 UPD1 build 23506",
    0x59f2 -> "VS2015 [14.0] build 23026",
    0x527a -> "VS2013 Nobemver CTP [12.0] build 21114",
    0x9eb5 -> "VS2013 UPD5 build 40629",
    0x797d -> "VS2013 UPD4 build 31101",
    0x7803 -> "VS2013 UPD3 build 30723",
    0x7725 -> "VS2013 UPD2 build 30501",
    0x7674 -> "VS2013 Update2 RC [12.0] build 30324",
    0x520d -> "VS2013 build 21005",
    0x515b -> "VS2013 RC [12.0] build 20827",
    0x5089 -> "VS2013 Preview [12.0] build 20617",
    0xee66 -> "VS2012 UPD4 build 61030",
    0xecc2 -> "VS2012 UPD3 build 60610",
    0xeb9b -> "VS2012 UPD2 build 60315",
    0xc7a2 -> "VS2012 UPD1 build 51106",
    0xc751 -> "VS2012 November CTP [11.0] build 51025",
    0xc627 -> "VS2012 build 50727",
    0x9d1b -> "VS2010 SP1 build 40219",
    0x766f -> "VS2010 build 30319",
    0x520b -> "VS2010 Beta 2 [10.0] build 21003",
    0x501a -> "VS2010 Beta 1 [10.0] build 20506",
    0x7809 -> "VS2008 SP1 build 30729",
    0x521e -> "VS2008 build 21022",
    0x50e2 -> "VS2008 Beta 2 [9.0] build 20706",
    0xc627 -> "VS2005 build 50727",
    0xc490 -> "VS2005 [8.0] build 50320",
    0xc427 -> "VS2005 Beta 2 [8.0] build 50215",
    0x9e9f -> "VS2005 Beta 1 [8.0] build 40607",
    0x9d76 -> "Windows Server 2003 SP1 DDK (for AMD64) build 40310",
    0x0bec -> "VS2003 (.NET) build 3052",
    0x178e -> "VS2003 (.NET) SP1 build 6030",
    0x0fc3 -> "Windows Server 2003 SP1 DDK build 4035",
    0x0c05 -> "VS2003 (.NET) build 3077",
    0x24fa -> "VS2002 (.NET) build 9466",
    0x23d8 -> "Windows XP SP1 DDK build 9176",
    0x2636 -> "VS98 (6.0) SP6 build 8804",
    0x2306 -> "VC++ 6.0 SP5 build 8804",
    0x1fe8 -> "VS98 (6.0) build 8168",
    0x20ff -> "VC++ 6.0 SP5 imp/exp build 8447",
    0x06c7 -> "VS98 (6.0) SP6 cvtres build 1736",
    0x06b8 -> "VS98 (6.0) cvtres build 1720",
    0x0000 -> "Unmarked objects"
  )
  /**
   * From https://github.com/kirschju/richheader/blob/master/prodids.py
   */
  val prodIdMap = Map(
    0x0000 -> "Unknown",
    0x0001 -> "Import0",
    0x0002 -> "Linker510",
    0x0003 -> "Cvtomf510",
    0x0004 -> "Linker600",
    0x0005 -> "Cvtomf600",
    0x0006 -> "Cvtres500",
    0x0007 -> "Utc11_Basic",
    0x0008 -> "Utc11_C",
    0x0009 -> "Utc12_Basic",
    0x000a -> "Utc12_C",
    0x000b -> "Utc12_CPP",
    0x000c -> "AliasObj60",
    0x000d -> "VisualBasic60",
    0x000e -> "Masm613",
    0x000f -> "Masm710",
    0x0010 -> "Linker511",
    0x0011 -> "Cvtomf511",
    0x0012 -> "Masm614",
    0x0013 -> "Linker512",
    0x0014 -> "Cvtomf512",
    0x0015 -> "Utc12_C_Std",
    0x0016 -> "Utc12_CPP_Std",
    0x0017 -> "Utc12_C_Book",
    0x0018 -> "Utc12_CPP_Book",
    0x0019 -> "Implib700",
    0x001a -> "Cvtomf700",
    0x001b -> "Utc13_Basic",
    0x001c -> "Utc13_C",
    0x001d -> "Utc13_CPP",
    0x001e -> "Linker610",
    0x001f -> "Cvtomf610",
    0x0020 -> "Linker601",
    0x0021 -> "Cvtomf601",
    0x0022 -> "Utc12_1_Basic",
    0x0023 -> "Utc12_1_C",
    0x0024 -> "Utc12_1_CPP",
    0x0025 -> "Linker620",
    0x0026 -> "Cvtomf620",
    0x0027 -> "AliasObj70",
    0x0028 -> "Linker621",
    0x0029 -> "Cvtomf621",
    0x002a -> "Masm615",
    0x002b -> "Utc13_LTCG_C",
    0x002c -> "Utc13_LTCG_CPP",
    0x002d -> "Masm620",
    0x002e -> "ILAsm100",
    0x002f -> "Utc12_2_Basic",
    0x0030 -> "Utc12_2_C",
    0x0031 -> "Utc12_2_CPP",
    0x0032 -> "Utc12_2_C_Std",
    0x0033 -> "Utc12_2_CPP_Std",
    0x0034 -> "Utc12_2_C_Book",
    0x0035 -> "Utc12_2_CPP_Book",
    0x0036 -> "Implib622",
    0x0037 -> "Cvtomf622",
    0x0038 -> "Cvtres501",
    0x0039 -> "Utc13_C_Std",
    0x003a -> "Utc13_CPP_Std",
    0x003b -> "Cvtpgd1300",
    0x003c -> "Linker622",
    0x003d -> "Linker700",
    0x003e -> "Export622",
    0x003f -> "Export700",
    0x0040 -> "Masm700",
    0x0041 -> "Utc13_POGO_I_C",
    0x0042 -> "Utc13_POGO_I_CPP",
    0x0043 -> "Utc13_POGO_O_C",
    0x0044 -> "Utc13_POGO_O_CPP",
    0x0045 -> "Cvtres700",
    0x0046 -> "Cvtres710p",
    0x0047 -> "Linker710p",
    0x0048 -> "Cvtomf710p",
    0x0049 -> "Export710p",
    0x004a -> "Implib710p",
    0x004b -> "Masm710p",
    0x004c -> "Utc1310p_C",
    0x004d -> "Utc1310p_CPP",
    0x004e -> "Utc1310p_C_Std",
    0x004f -> "Utc1310p_CPP_Std",
    0x0050 -> "Utc1310p_LTCG_C",
    0x0051 -> "Utc1310p_LTCG_CPP",
    0x0052 -> "Utc1310p_POGO_I_C",
    0x0053 -> "Utc1310p_POGO_I_CPP",
    0x0054 -> "Utc1310p_POGO_O_C",
    0x0055 -> "Utc1310p_POGO_O_CPP",
    0x0056 -> "Linker624",
    0x0057 -> "Cvtomf624",
    0x0058 -> "Export624",
    0x0059 -> "Implib624",
    0x005a -> "Linker710",
    0x005b -> "Cvtomf710",
    0x005c -> "Export710",
    0x005d -> "Implib710",
    0x005e -> "Cvtres710",
    0x005f -> "Utc1310_C",
    0x0060 -> "Utc1310_CPP",
    0x0061 -> "Utc1310_C_Std",
    0x0062 -> "Utc1310_CPP_Std",
    0x0063 -> "Utc1310_LTCG_C",
    0x0064 -> "Utc1310_LTCG_CPP",
    0x0065 -> "Utc1310_POGO_I_C",
    0x0066 -> "Utc1310_POGO_I_CPP",
    0x0067 -> "Utc1310_POGO_O_C",
    0x0068 -> "Utc1310_POGO_O_CPP",
    0x0069 -> "AliasObj710",
    0x006a -> "AliasObj710p",
    0x006b -> "Cvtpgd1310",
    0x006c -> "Cvtpgd1310p",
    0x006d -> "Utc1400_C",
    0x006e -> "Utc1400_CPP",
    0x006f -> "Utc1400_C_Std",
    0x0070 -> "Utc1400_CPP_Std",
    0x0071 -> "Utc1400_LTCG_C",
    0x0072 -> "Utc1400_LTCG_CPP",
    0x0073 -> "Utc1400_POGO_I_C",
    0x0074 -> "Utc1400_POGO_I_CPP",
    0x0075 -> "Utc1400_POGO_O_C",
    0x0076 -> "Utc1400_POGO_O_CPP",
    0x0077 -> "Cvtpgd1400",
    0x0078 -> "Linker800",
    0x0079 -> "Cvtomf800",
    0x007a -> "Export800",
    0x007b -> "Implib800",
    0x007c -> "Cvtres800",
    0x007d -> "Masm800",
    0x007e -> "AliasObj800",
    0x007f -> "PhoenixPrerelease",
    0x0080 -> "Utc1400_CVTCIL_C",
    0x0081 -> "Utc1400_CVTCIL_CPP",
    0x0082 -> "Utc1400_LTCG_MSIL",
    0x0083 -> "Utc1500_C",
    0x0084 -> "Utc1500_CPP",
    0x0085 -> "Utc1500_C_Std",
    0x0086 -> "Utc1500_CPP_Std",
    0x0087 -> "Utc1500_CVTCIL_C",
    0x0088 -> "Utc1500_CVTCIL_CPP",
    0x0089 -> "Utc1500_LTCG_C",
    0x008a -> "Utc1500_LTCG_CPP",
    0x008b -> "Utc1500_LTCG_MSIL",
    0x008c -> "Utc1500_POGO_I_C",
    0x008d -> "Utc1500_POGO_I_CPP",
    0x008e -> "Utc1500_POGO_O_C",
    0x008f -> "Utc1500_POGO_O_CPP",
    0x0090 -> "Cvtpgd1500",
    0x0091 -> "Linker900",
    0x0092 -> "Export900",
    0x0093 -> "Implib900",
    0x0094 -> "Cvtres900",
    0x0095 -> "Masm900",
    0x0096 -> "AliasObj900",
    0x0097 -> "Resource",
    0x0098 -> "AliasObj1000",
    0x0099 -> "Cvtpgd1600",
    0x009a -> "Cvtres1000",
    0x009b -> "Export1000",
    0x009c -> "Implib1000",
    0x009d -> "Linker1000",
    0x009e -> "Masm1000",
    0x009f -> "Phx1600_C",
    0x00a0 -> "Phx1600_CPP",
    0x00a1 -> "Phx1600_CVTCIL_C",
    0x00a2 -> "Phx1600_CVTCIL_CPP",
    0x00a3 -> "Phx1600_LTCG_C",
    0x00a4 -> "Phx1600_LTCG_CPP",
    0x00a5 -> "Phx1600_LTCG_MSIL",
    0x00a6 -> "Phx1600_POGO_I_C",
    0x00a7 -> "Phx1600_POGO_I_CPP",
    0x00a8 -> "Phx1600_POGO_O_C",
    0x00a9 -> "Phx1600_POGO_O_CPP",
    0x00aa -> "Utc1600_C",
    0x00ab -> "Utc1600_CPP",
    0x00ac -> "Utc1600_CVTCIL_C",
    0x00ad -> "Utc1600_CVTCIL_CPP",
    0x00ae -> "Utc1600_LTCG_C",
    0x00af -> "Utc1600_LTCG_CPP",
    0x00b0 -> "Utc1600_LTCG_MSIL",
    0x00b1 -> "Utc1600_POGO_I_C",
    0x00b2 -> "Utc1600_POGO_I_CPP",
    0x00b3 -> "Utc1600_POGO_O_C",
    0x00b4 -> "Utc1600_POGO_O_CPP",
    0x00b5 -> "AliasObj1010",
    0x00b6 -> "Cvtpgd1610",
    0x00b7 -> "Cvtres1010",
    0x00b8 -> "Export1010",
    0x00b9 -> "Implib1010",
    0x00ba -> "Linker1010",
    0x00bb -> "Masm1010",
    0x00bc -> "Utc1610_C",
    0x00bd -> "Utc1610_CPP",
    0x00be -> "Utc1610_CVTCIL_C",
    0x00bf -> "Utc1610_CVTCIL_CPP",
    0x00c0 -> "Utc1610_LTCG_C",
    0x00c1 -> "Utc1610_LTCG_CPP",
    0x00c2 -> "Utc1610_LTCG_MSIL",
    0x00c3 -> "Utc1610_POGO_I_C",
    0x00c4 -> "Utc1610_POGO_I_CPP",
    0x00c5 -> "Utc1610_POGO_O_C",
    0x00c6 -> "Utc1610_POGO_O_CPP",
    0x00c7 -> "AliasObj1100",
    0x00c8 -> "Cvtpgd1700",
    0x00c9 -> "Cvtres1100",
    0x00ca -> "Export1100",
    0x00cb -> "Implib1100",
    0x00cc -> "Linker1100",
    0x00cd -> "Masm1100",
    0x00ce -> "Utc1700_C",
    0x00cf -> "Utc1700_CPP",
    0x00d0 -> "Utc1700_CVTCIL_C",
    0x00d1 -> "Utc1700_CVTCIL_CPP",
    0x00d2 -> "Utc1700_LTCG_C",
    0x00d3 -> "Utc1700_LTCG_CPP",
    0x00d4 -> "Utc1700_LTCG_MSIL",
    0x00d5 -> "Utc1700_POGO_I_C",
    0x00d6 -> "Utc1700_POGO_I_CPP",
    0x00d7 -> "Utc1700_POGO_O_C",
    0x00d8 -> "Utc1700_POGO_O_CPP",
    0x00d9 -> "AliasObj1200",
    0x00da -> "Cvtpgd1800",
    0x00db -> "Cvtres1200",
    0x00dc -> "Export1200",
    0x00dd -> "Implib1200",
    0x00de -> "Linker1200",
    0x00df -> "Masm1200",
    0x00e0 -> "Utc1800_C",
    0x00e1 -> "Utc1800_CPP",
    0x00e2 -> "Utc1800_CVTCIL_C",
    0x00d3 -> "Utc1800_CVTCIL_CPP",
    0x00e4 -> "Utc1800_LTCG_C",
    0x00e5 -> "Utc1800_LTCG_CPP",
    0x00e6 -> "Utc1800_LTCG_MSIL",
    0x00e7 -> "Utc1800_POGO_I_C",
    0x00e8 -> "Utc1800_POGO_I_CPP",
    0x00e9 -> "Utc1800_POGO_O_C",
    0x00ea -> "Utc1800_POGO_O_CPP",
    0x00eb -> "AliasObj1210",
    0x00ec -> "Cvtpgd1810",
    0x00ed -> "Cvtres1210",
    0x00ee -> "Export1210",
    0x00ef -> "Implib1210",
    0x00f0 -> "Linker1210",
    0x00f1 -> "Masm1210",
    0x00f2 -> "Utc1810_C",
    0x00f3 -> "Utc1810_CPP",
    0x00f4 -> "Utc1810_CVTCIL_C",
    0x00f5 -> "Utc1810_CVTCIL_CPP",
    0x00f6 -> "Utc1810_LTCG_C",
    0x00f7 -> "Utc1810_LTCG_CPP",
    0x00f8 -> "Utc1810_LTCG_MSIL",
    0x00f9 -> "Utc1810_POGO_I_C",
    0x00fa -> "Utc1810_POGO_I_CPP",
    0x00fb -> "Utc1810_POGO_O_C",
    0x00fc -> "Utc1810_POGO_O_CPP",
    0x00fd -> "AliasObj1400",
    0x00fe -> "Cvtpgd1900",
    0x00ff -> "Cvtres1400",
    0x0100 -> "Export1400",
    0x0101 -> "Implib1400",
    0x0102 -> "Linker1400",
    0x0103 -> "Masm1400",
    0x0104 -> "Utc1900_C",
    0x0105 -> "Utc1900_CPP",
    0x0106 -> "Utc1900_CVTCIL_C",
    0x0107 -> "Utc1900_CVTCIL_CPP",
    0x0108 -> "Utc1900_LTCG_C",
    0x0109 -> "Utc1900_LTCG_CPP",
    0x010a -> "Utc1900_LTCG_MSIL",
    0x010b -> "Utc1900_POGO_I_C",
    0x010c -> "Utc1900_POGO_I_CPP",
    0x010d -> "Utc1900_POGO_O_C",
    0x010e -> "Utc1900_POGO_O_CPP"
  )

}
