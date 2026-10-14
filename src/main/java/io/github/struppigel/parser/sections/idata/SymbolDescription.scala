package io.github.struppigel.parser.sections.idata

import java.util.Optional

class SymbolDescription(
    symbolName: String, 
    description: Optional[String], 
    category: String, 
    subCategory: Optional[String]) {

  def getSymbolName(): String = symbolName
  def getDescription(): Optional[String] = description
  def getCategory(): String = category
  def getSubCategory(): Optional[String] = subCategory
  
}