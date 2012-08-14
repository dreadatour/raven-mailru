# -*- coding: utf-8 -*-
from mock import Mock
from unittest import TestCase
from raven_mailru.processors import SanitizeMpopProcessor


COOKIE = '1234567890:050a0f170a021b04041d064568515c455f:test@mail.ru:'
SANITIZED = '1234567890:********:test@mail.ru:'


class SanitizeMpopProcessorTest(TestCase):

    def test_http(self):
        data = {
            'sentry.interfaces.Http': {
                'cookies': {
                    'Mpop': COOKIE,
                    'language': 'ru_RU',
                    'foo': '12345:32384938032:test:',
                },
                'headers': {
                    'Accept-Language': 'en-us,en;q=0.5',
                    'Cookie': (
                        'csrftoken=4a4baPyR8yDlT0fgSmAHj2dlr2Z6ZBCJ; '
                        'Mpop=' + COOKIE + '; '
                        'language=ru_RU'
                    ),
                }
            }
        }

        proc = SanitizeMpopProcessor(Mock())
        result = proc.process(data)

        http = result['sentry.interfaces.Http']
        self.assertEqual(SANITIZED, http['cookies']['Mpop'])
        self.assertIn(SANITIZED, http['headers']['Cookie'])

    def test_stacktrace(self):
        request = (
            "<WSGIRequest\n"
            "path:/500/,\n"
            "GET:<QueryDict: {}>,\n"
            "POST:<QueryDict: {}>,\n"
            "COOKIES:{'Mpop': '" + COOKIE + "',\n"
            " 'csrftoken': '4a4baPyR8yDlT0fgSmAHj2dlr2Z6ZBCJ',\n"
            " 'language': 'ru_RU...'"
        )
        data = {
            'sentry.interfaces.Stacktrace': {
                'frames': [
                    {
                        'vars': {
                            'request': request
                        }
                    }
                ]
            }
        }

        proc = SanitizeMpopProcessor(Mock())
        result = proc.process(data)

        stack = result['sentry.interfaces.Stacktrace']
        for frame in stack['frames']:
            self.assertIn(SANITIZED, frame['vars']['request'])
