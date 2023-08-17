VERSION := $(shell sed -n 's/^Version: //p' htgettoken.spec)

man: htgettoken.html htdestroytoken.html htdecodetoken.html httokensh.html

%.html : %.1
	groff -mandoc -Thtml $< >$@

# For koji builds
sources:
	@tar cf - *  --transform="s,^,htgettoken-$(VERSION)/," | gzip --best > htgettoken-$(VERSION).tar.gz
