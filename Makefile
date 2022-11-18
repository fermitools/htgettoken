VERSION := $(shell sed -n 's/^Version: //p' htgettoken.spec)

htgettoken.html: htgettoken.1
	groff -mandoc -Thtml htgettoken.1 >htgettoken.html

# For koji builds
sources:
	@tar cf - *  --transform="s,^,htgettoken-$(VERSION)/," | gzip --best > htgettoken-$(VERSION).tar.gz
