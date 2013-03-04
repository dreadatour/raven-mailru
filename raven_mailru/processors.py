# -*- coding: utf-8 -*-
"""
Sentry processors for mail.ru project.
Remove all mail.ru sensitive data from sentry report.
"""
import re
import base64

from raven.processors import Processor


class SanitizeMpopProcessor(Processor):
    """
    Replaces part of Mpop cookie with asterisks
    """
    SEARCH_RE = re.compile(r'^(\d+:)(\w+)(:.+)')

    def sanitize_cookie(self, value):
        """
        Sanitize Mpop cookie.
        """
        return self.SEARCH_RE.sub(r'\1********\3', value)

    def recursive_cookie_clear(self, var):
        """
        Recursive walk through 'var' dict and sanitize all 'cookies' vars.
        """
        if not isinstance(var, dict):
            return

        for key in var:
            if key.lower() not in ('cookie', 'cookies'):
                self.recursive_cookie_clear(var[key])
                continue

            if not hasattr(var[key], '__iter__'):
                continue

            for cookie_key in var[key]:
                if cookie_key.lower() == 'mpop':
                    cookie_value = self.sanitize_cookie(var[key][cookie_key])
                    var[key][cookie_key] = cookie_value

    def filter_stacktrace(self, data):
        """
        Recursive walk through stacktrace and sanitize
        all 'Mpop' vars in request.
        """
        if 'frames' not in data:
            return

        for frame in data['frames']:
            if 'vars' not in frame:
                continue  # skip frame if no 'vars' in it

            self.recursive_cookie_clear(frame['vars'])

            request = frame['vars'].get('request')
            if not isinstance(request, basestring):
                continue  # skip frame if no 'request' string in it

            bits = []
            for bit in request.split('\n'):
                if 'Mpop' in bit:
                    key, value = bit.split(': \'', 1)
                    bit = ': \''.join((key, self.sanitize_cookie(value)))
                bits.append(bit)

            frame['vars']['request'] = '\n'.join(bits)

    def filter_http(self, data):
        """
        Sanitize http data: cookies and headers.
        """
        for n in ('cookies', 'headers'):

            if n not in data:
                continue

            if 'Mpop' in data[n]:
                data[n]['Mpop'] = self.sanitize_cookie(data[n]['Mpop'])

            if 'Cookie' in data[n]:
                bits = []
                for bit in data[n]['Cookie'].split('; '):
                    key, value = bit.split('=', 1)
                    if key == 'Mpop':
                        value = self.sanitize_cookie(value)
                    bits.append((key, value))

                data[n]['Cookie'] = '; '.join('='.join(k) for k in bits)

            if 'Authorization' in data[n]:
                if data[n]['Authorization'].lower().startswith('basic '):
                    username = base64.b64decode(
                        data[n]['Authorization'][6:]
                    ).split(':')[0]
                    data[n]['Authorization'] = 'Basic %s:********' % username

    def process(self, data, **kwargs):
        """
        Process sentry data - strip all mail.ru sensitive data.
        """
        if 'sentry.interfaces.Stacktrace' in data:
            self.filter_stacktrace(data['sentry.interfaces.Stacktrace'])

        if 'sentry.interfaces.Http' in data:
            self.filter_http(data['sentry.interfaces.Http'])

        return data
