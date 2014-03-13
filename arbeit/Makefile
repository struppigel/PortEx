PDFLATEXFLAGS=-interaction=nonstopmode

export TEXINPUTS=./custom_libraries//:

.SILENT:
.PHONY: clean printstats

all: arbeit.pdf printstats

dvi: arbeit.dvi printstats

initialrun:
	pdflatex $(PDFLATEXFLAGS) arbeit

arbeit.pdf: *.tex arbeit.glo arbeit.acr arbeit.bbl listings/* *.sty arbeit.ind
	pdflatex $(PDFLATEXFLAGS) arbeit.tex
	pdflatex $(PDFLATEXFLAGS) arbeit.tex

arbeit.bbl: references.bib
	bibtex arbeit

arbeit.glo arbeit.acr: *.tex
	pdflatex $(PDFLATEXFLAGS) arbeit
	./makeglos.pl arbeit

arbeit.ind: arbeit.idx
	pdflatex $(PDFLATEXFLAGS) arbeit
	makeindex arbeit

arbeit.idx:
	pdflatex $(PDFLATEXFLAGS) arbeit

listings/*:

arbeit.dvi: *.tex arbeit.glo arbeit.acr arbeit.bbl listings/* *.sty
	latex arbeit
	latex arbeit

simple: initialrun printstats

printstats:
	echo -n "lines:               "; detex *.tex 2>/dev/null | wc -l
	echo -n "words:               "; detex *.tex 2>/dev/null | wc -w
	echo -n "underfull:           "; grep -c Underfull arbeit.log
	echo -n "overfull:            "; grep -c Overfull arbeit.log
#	echo -n "undefined refs:      "; grep undefined arbeit.log | grep -c Reference
#	echo -n "undefined citations: "; grep undefined arbeit.log | grep -c Citation

clean:
	rm -f *.aux *.alg *.blg *.glg *.lo? *.toc *.acn *.glg *.idx *.pdf *.dvi *.ps *.acr *.bbl *.glo *.ist *.gls *.tdo *.ind *.ilg *.out

