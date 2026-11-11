"""Whether this machine has a compiler the hive can confine (Clang with a closed VFS and inline assembly disabled).

Hive tests that compile skip without one, as the hive itself refuses to compile without one."""

import tempfile
from functools import lru_cache

from hive import languages, queen


@lru_cache(maxsize=None)
def confined(language="c"):
    try:
        queen.Build(tempfile.mkdtemp(prefix="hive-compiler-"), language=languages.LANGUAGES[language]).ensure_confinement()
        return True
    except Exception:
        return False
