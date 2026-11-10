from datetime import datetime
from unittest.mock import patch

from webauthn.helpers import validate_certificate_chain


def patch_validate_certificate_chain_x509store_getter(func):
    """
    This is a very purpose-built decorator to help set a fixed time for X.509 certificate chain
    validation in unittests. It makes the following assumptions, all of which must be true for this
    decorator to remain useful:

    - X.509 certificate chain validation occurs in **webauthn/helpers/validate_certificate_chain.py::**`validate_certificate_chain`
    - `validate_certificate_chain(...)` obtains its validation instant from `_get_verification_time`
    - **webauthn/helpers/__init__.py** continues to re-export `validate_certificate_chain`

    Usage:

    ```
    from unittest import TestCase
    from datetime import datetime

    from .helpers.x509store import patch_validate_certificate_chain_x509store_getter

    class TestX509Validation(TestCase):
        @patch_validate_certificate_chain_x509store_getter
        def test_validate_x509_chain(self, verification_time):
            verification_time(datetime(2021, 9, 1, 0, 0, 0))
            # ...
    ```
    """

    def wrapper(*args, **kwargs):
        """
        Using `inspect.getmodule(...)` below helps deal with the fact that, in Python 3.9 and
        Python 3.10, patching
        `webauthn.helpers.validate_certificate_chain._get_verification_time`
        errors out because `webauthn.helpers.validate_certificate_chain` is understood to be the
        function re-exported via `__all__` in **webauthn/helpers/__init__.py**, not the module of
        the same name.
        """
        import inspect

        with patch.object(
            inspect.getmodule(validate_certificate_chain),
            "_get_verification_time",
        ) as mock_get_verification_time:
            mock_get_verification_time.return_value = None

            def set_verification_time(verification_time: datetime) -> None:
                mock_get_verification_time.return_value = verification_time

            return func(*args, set_verification_time, **kwargs)

    return wrapper
