# Synthetic analysis input. The analysis parses this file; it does not run it.
from pathlib import Path

target = Path('product.py')
old = target.read_text()
replacement = '''def answer():
    return 2
'''
target.write_text(old.replace('def answer():\n    return 1\n', replacement))
