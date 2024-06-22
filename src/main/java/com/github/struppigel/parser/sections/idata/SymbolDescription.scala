package com.github.struppigel.parser.sections.idata

import com.google.common.base.Optional

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