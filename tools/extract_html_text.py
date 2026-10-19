#!/usr/bin/env python3
# extract_html_text.py 1.0 - extracts the main text of a saved HTML page (for example a raw
# Wayback Machine capture, `id_` address) as blocks of plain text: from the last block that
# starts with START before the first block that starts with END (END itself excluded).
# Links are kept as their text, without addresses. <br> becomes a line break.
# Usage: extract_html_text.py FILE.html START END SEP [lists]
#   SEP:   'blank' = a blank line between blocks, 'line' = one block per line
#   lists: list items with a marker ("1." for <ol>, "-" for <ul>) and an indent of 3 spaces per level
# Used for the text files in sources/ (D1 and D4-D8 from the Wayback Machine, EP1-EP3, EP7, EP7a).
import sys
from html.parser import HTMLParser

VERSION = "1.0"
BLOCK = {'h1','h2','h3','h4','h5','h6','p','li','td','th','dt','dd','blockquote','div','section','article','main','header','footer','nav','ul','ol','tr','table','aside','figure','figcaption','pre'}
SKIP = {'script','style','noscript','svg','template','head','button'}

class Extractor(HTMLParser):
    def __init__(self, lists):
        super().__init__(convert_charrefs=True)
        self.buf = []; self.out = []; self.skip = 0; self.lists = lists; self.lstack = []; self.prefix = ''
    def flush(self):
        raw = ''.join(self.buf)
        lines = [' '.join(l.split()) for l in raw.split('\n\x00')]
        t = '\n'.join(l for l in lines if l)
        if t: self.out.append(self.prefix + t)
        self.buf = []; self.prefix = ''
    def handle_starttag(self, tag, attrs):
        if tag in SKIP: self.skip += 1; return
        if tag == 'br': self.buf.append('\n\x00'); return
        if tag in BLOCK: self.flush()
        if self.lists:
            if tag in ('ol', 'ul'): self.lstack.append([tag, 0])
            elif tag == 'li' and self.lstack:
                self.lstack[-1][1] += 1
                kind, n = self.lstack[-1]
                self.prefix = '   ' * (len(self.lstack) - 1) + (f'{n}. ' if kind == 'ol' else '- ')
    def handle_endtag(self, tag):
        if tag in SKIP: self.skip = max(0, self.skip - 1); return
        if tag in BLOCK: self.flush()
        if self.lists and tag in ('ol', 'ul') and self.lstack: self.lstack.pop()
    def handle_data(self, data):
        if not self.skip: self.buf.append(data)

def extract(html, start, end, sep, lists=False):
    """Returns the blocks from the last block starting with `start` before the first block
    starting with `end`, joined with a blank line ('blank') or a line break ('line')."""
    p = Extractor(lists); p.feed(html); p.flush()
    b = p.out
    try:
        j = next(k for k, x in enumerate(b) if x.startswith(end))
    except StopIteration:
        sys.exit(f"ERROR: no block starts with END {end!r}")
    starts = [k for k, x in enumerate(b[:j]) if x.startswith(start)]
    if not starts:
        sys.exit(f"ERROR: no block before END starts with START {start!r}")
    return ('\n\n' if sep == 'blank' else '\n').join(b[max(starts):j]) + '\n'

def main(argv):
    if len(argv) < 5 or argv[4] not in ('blank', 'line'):
        sys.exit("Usage: extract_html_text.py FILE.html START END SEP [lists]   (SEP: blank | line)")
    f, start, end, sep = argv[1:5]
    with open(f, encoding='utf-8') as fh:
        html = fh.read()
    sys.stdout.write(extract(html, start, end, sep, len(argv) > 5 and argv[5] == 'lists'))

if __name__ == '__main__':
    main(sys.argv)
