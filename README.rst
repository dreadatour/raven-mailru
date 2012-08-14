Raven-mailru
============

Data processor for `Raven`_

Usage
-----

::
    RAVEN_CONFIG = {
        'dsn': '<put your dsn here>',
        'processors': (
            'raven_mailru.processors.SanitizeMpopProcessor',
        )
    }

.. _Raven: https://github.com/getsentry/raven-python
