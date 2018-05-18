OUTPUT_HTML = /tmp/README.html

default: docs

docs:
	pandoc --normalize -sS -f markdown -t html header.md --template=template.html >> $(OUTPUT_HTML)
	pandoc --normalize -sS -f markdown -t html releases.md --template=template.html >> $(OUTPUT_HTML)
	pandoc --normalize -sS -f markdown_mmd -t html body.md --template=template.html --table-of-contents >> $(OUTPUT_HTML)

