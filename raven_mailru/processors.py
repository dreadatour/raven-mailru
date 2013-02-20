# -*- coding: utf-8 -*-
import re
import base64

from raven.processors import Processor


class SanitizeMpopProcessor(Processor):
    """
    Replaces part of Mpop cookie with asterisks
    """
    SEARCH_RE = re.compile(r'^(\d+:)(\w+)(:.+)')

    def sanitize(self, value):
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
                    var[key][cookie_key] = self.sanitize(var[key][cookie_key])

    def filter_stacktrace(self, data):
        if 'frames' not in data:
            return

        for frame in data['frames']:
            if 'vars' not in frame:
                continue

            self.recursive_cookie_clear(frame['vars'])

            if 'request' in frame['vars']:
                bits = []
                for bit in frame['vars']['request'].split('\n'):
                    if 'Mpop' in bit:
                        key, value = bit.split(': \'', 1)
                        bit = ': \''.join((key, self.sanitize(value)))
                    bits.append(bit)

                frame['vars']['request'] = '\n'.join(bits)

    def filter_http(self, data):
        for n in ('cookies', 'headers'):

            if n not in data:
                continue

            if 'Mpop' in data[n]:
                data[n]['Mpop'] = self.sanitize(data[n]['Mpop'])

            if 'Cookie' in data[n]:
                bits = []
                for bit in data[n]['Cookie'].split('; '):
                    key, value = bit.split('=', 1)
                    if key == 'Mpop':
                        value = self.sanitize(value)
                    bits.append((key, value))

                data[n]['Cookie'] = '; '.join('='.join(k) for k in bits)

            if 'Authorization' in data[n]:
                if data[n]['Authorization'].lower().startswith('basic '):
                    username = base64.b64decode(
                        data[n]['Authorization'][6:]
                    ).split(':')[0]
                    data[n]['Authorization'] = 'Basic %s:********' % username

    def process(self, data, **kwargs):

        if 'sentry.interfaces.Stacktrace' in data:
            self.filter_stacktrace(data['sentry.interfaces.Stacktrace'])

        if 'sentry.interfaces.Http' in data:
            self.filter_http(data['sentry.interfaces.Http'])

        return data
