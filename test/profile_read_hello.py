import pathlib
import sys

print(pathlib.Path(sys.argv[1]).read_text().strip())
