'''
Some helpful utlity functions and classes.
'''
import random

class RandomMac(object):

    def __init__(self):
        self.used_macs = set()

    def get_mac(self):
        temp = self._random_mac()
        while True:
            if temp not in self.used_macs:
                self.used_macs.add(temp)
                return temp
            temp = self._random_mac()

    def _random_mac(self):
        def get_random_octet():
            data = '{:x}'.format(random.randint(0, 255))
            if len(data) < 2:
                data = '0' + data
            return data
        return '34:34:34:{0}:{1}:{2}'.format(get_random_octet(),
                                             get_random_octet(),
                                             get_random_octet())
