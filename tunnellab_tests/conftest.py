"""Pytest bootstrap: make the repository root importable so the laboratory
package (``tunnellab``) can be imported regardless of the invocation dir.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
