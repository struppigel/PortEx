# This file generates files required to use the listings package.
#
# (c) 2007 Brooks Moses
#
# This file is distributed under the terms of the LaTeX Project Public
# License from CTAN archives in directory  macros/latex/base/lppl.txt.
# Either version 1.3 or, at your option, any later version.

.PHONY: listings pdf pdf-devel all

listings: listings.sty

pdf: listings.pdf

pdf-devel: listings-devel.pdf

all: listings pdf pdf-devel


listings.sty: listings.dtx listings.ins lstdrvrs.dtx
	tex listings.ins

listings.pdf: listings.sty
	rm -f ltxdoc.cfg
	pdflatex listings.dtx
	makeindex -s gind.ist listings
	pdflatex listings.dtx
	pdflatex listings.dtx

listings-devel.pdf: listings.sty
	rm -rf ltxdoc.cfg
	echo "\AtBeginDocument{\AlsoImplementation}" > ltxdoc.cfg
	pdflatex -jobname=listings-devel listings.dtx
	makeindex -s gind.ist listings-devel
	pdflatex -jobname=listings-devel listings.dtx
	pdflatex -jobname=listings-devel listings.dtx
	rm -rf ltxdoc.cfg
