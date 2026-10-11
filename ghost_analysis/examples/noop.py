# Synthetic analysis input: a possible write can still leave its target unchanged.
from pathlib import Path

target = Path('product.py')
target.write_text(target.read_text())
