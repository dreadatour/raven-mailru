# -*- coding: utf-8 -*-
import re

from raven.processors import Processor


class SanitizeMpopProcessor(Processor):
    """
    Replaces part of Mpop cookie with asterisks
    """
    SEARCH_RE = re.compile(r'^(\d+:)(\w+)(:.+)')

    def sanitize(self, value):
        return self.SEARCH_RE.sub(r'\1********\3', value)

    def filter_stacktrace(self, data):
        if 'frames' not in data:
            return

        for frame in data['frames']:
            if 'vars' not in frame:
                continue

            if 'request' in frame['vars']:
                bits = []
                for bit in frame['vars']['request'].split('\n'):
                    print bit
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

    def process(self, data, **kwargs):

        if 'sentry.interfaces.Stacktrace' in data:
            self.filter_stacktrace(data['sentry.interfaces.Stacktrace'])

        if 'sentry.interfaces.Http' in data:
            self.filter_http(data['sentry.interfaces.Http'])

        return data
