import warnings

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)


@pytest.fixture
def env(tmp_path):
    from qg.testing import TestEnv

    e = TestEnv(tmp_path)
    yield e
    e.close()
