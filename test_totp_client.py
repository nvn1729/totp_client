# Copyright 2019 Naveen Sunkavally
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import unittest
import totp_client
import hashlib
from binascii import unhexlify
from base64 import b32encode
from configparser import ConfigParser

# Hotp reference examples here: https://tools.ietf.org/html/rfc4226#page-32
class TestHotp(unittest.TestCase):

    def setUp(self):
        # using default parameters: algorithm = sha1, digits = 6
        secret = unhexlify('3132333435363738393031323334353637383930')
        self.hotp = totp_client.Hotp(secret)

    def test_values(self):
        expected = [
            (0, '755224'),
            (1, '287082'),
            (2, '359152'),
            (3, '969429'),
            (4, '338314'),
            (5, '254676'),
            (6, '287922'),
            (7, '162583'),
            (8, '399871'),
            (9, '520489')
        ]
        
        for i, v in expected:
            self.assertEqual(v, self.hotp.at(i.to_bytes(8, byteorder='big')), msg='Failed otp comparison with i={}, code={}'.format(i, v))

# TOTP reference values from https://tools.ietf.org/html/rfc6238#page-14
class TestTotp(unittest.TestCase):

    def setUp(self):
        secret1 = unhexlify('3132333435363738393031323334353637383930')
        secret256 = unhexlify('3132333435363738393031323334353637383930313233343536373839303132')
        secret512 = unhexlify('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334')

        totp1 = totp_client.Totp(secret1, digits=8)
        totp256 = totp_client.Totp(secret256, digestmod=hashlib.sha256, digits=8)
        totp512 = totp_client.Totp(secret512, digestmod=hashlib.sha512, digits=8)

        self.totps = {
            'sha1': totp1,
            'sha256': totp256,
            'sha512': totp512
        }

    def test_values(self):
        expected = {
            59: [('sha1', '94287082'),  ('sha256', '46119246'), ('sha512', '90693936')],
            1111111109: [('sha1', '07081804'), ('sha256', '68084774'), ('sha512', '25091201')],
            1111111111: [('sha1', '14050471'), ('sha256', '67062674'), ('sha512', '99943326')],
            1234567890: [('sha1', '89005924'), ('sha256', '91819424'), ('sha512', '93441116')],
            2000000000: [('sha1', '69279037'), ('sha256', '90698825'), ('sha512', '38618901')],
            20000000000: [('sha1', '65353130'), ('sha256', '77737706'), ('sha512', '47863826')]
        }
        
        for t, v in expected.items():
            for alg, code in v:
                otp_test, remaining_test, t_test = self.totps[alg].at(t)
                self.assertEqual(code, otp_test, msg='Failed otp comparison with t={}, alg={}, code={}'.format(t, alg, code))
                self.assertEqual(t, t_test, msg='Failed time comparison with t={}, alg={}, code={}'.format(t, alg, code))
                self.assertEqual(30 - (t % 30), remaining_test, msg='Failed remaining time comparison with t={}, alg={}, code={}'.format(t, alg, code))


# use same totp secret and known values as in TestHotp test case
class TestParseConfigSingleKey(unittest.TestCase):

    def setUp(self):
        self.config = ConfigParser(defaults=totp_client.DEFAULTS)
        self.config["key1"] = {
            "Secret": b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8')
        }

    def test_parse(self):
        totps = totp_client.parse_config(self.config)

        self.assertEqual(1, len(totps))
        self.assertEqual('key1', totps[0][0])
        
        totp = totps[0][1]

        expected = [
            (0, '755224'),
            (1*30, '287082'),
            (2*30, '359152'),
            (3*30, '969429'),
            (4*30, '338314'),
            (5*30, '254676'),
            (6*30, '287922'),
            (7*30, '162583'),
            (8*30, '399871'),
            (9*30, '520489')
        ]
        
        for i, v in expected:
            self.assertEqual(v, totp.at(i)[0], msg='Failed otp comparison with i={}, code={}'.format(i, v))

# use same reference test keys and values as in TestTotp test case above
class TestParseConfigMultipleKeys(unittest.TestCase):

    def setUp(self):
        secret1 = b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8')
        secret256 = b32encode(unhexlify('3132333435363738393031323334353637383930313233343536373839303132')).decode('utf-8')
        secret512 = b32encode(unhexlify('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334')).decode('utf-8')

        self.config = ConfigParser(defaults=totp_client.DEFAULTS)
        self.config['key1'] = {
            'Secret': secret1,
            'Digits': '8'
        }
        self.config['key256'] = {
            'Secret': secret256,
            'Digits': '8',
            'Algorithm': 'sha256'
        }
        self.config['key512'] = {
            'Secret': secret512,
            'Digits': '8',
            'Algorithm': 'sha512'
        }

    def test_parse(self):

        totps = totp_client.parse_config(self.config)
        self.assertEqual(3, len(totps))

        totp_map = {}
        for key_name, totp in totps:
            totp_map[key_name] = totp

        expected = {
            59: [('key1', '94287082'),  ('key256', '46119246'), ('key512', '90693936')],
            1111111109: [('key1', '07081804'), ('key256', '68084774'), ('key512', '25091201')],
            1111111111: [('key1', '14050471'), ('key256', '67062674'), ('key512', '99943326')],
            1234567890: [('key1', '89005924'), ('key256', '91819424'), ('key512', '93441116')],
            2000000000: [('key1', '69279037'), ('key256', '90698825'), ('key512', '38618901')],
            20000000000: [('key1', '65353130'), ('key256', '77737706'), ('key512', '47863826')]
        }
        
        for t, v in expected.items():
            for key_name, code in v:
                otp_test, remaining_test, t_test = totp_map[key_name].at(t)
                self.assertEqual(code, otp_test, msg='Failed otp comparison with t={}, key name={}, code={}'.format(t, key_name, code))
                self.assertEqual(t, t_test, msg='Failed time comparison with t={}, key name={}, code={}'.format(t, key_name, code))
                self.assertEqual(30 - (t % 30), remaining_test, msg='Failed remaining time comparison with t={}, key name={}, code={}'.format(t, key_name, code))

class TestParseBadConfig(unittest.TestCase):

    def get_config(self):
        return ConfigParser(defaults=totp_client.DEFAULTS)

    def test_missing_secret(self):
        config = self.get_config()
        config['key1'] = {}
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

    def test_bad_secret(self):
        config = self.get_config()
        config['key1'] = {'Secret': '9afu9a0d'}
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

    def test_digits_not_numeric(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Digits': '6f'
        }
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

    def test_digits_out_of_range_upper(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Digits': '10'
        }
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

    def test_digits_out_of_range_lower(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Digits': '5'
        }
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

    def test_empty_digits(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Digits': ''
        }
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

    def test_period_not_numeric(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Period': '30f'
        }
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

    def test_invalid_period(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Period': '45'
        }
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

    def test_empty_period(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Period': ''
        }
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

    def test_invalid_algorithm(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Algorithm': 'sha384'
        }
        with self.assertRaises(Exception):
            totp_client.parse_config(config)
    
    def test_empty_algorithm(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Algorithm': ''
        }
        with self.assertRaises(Exception):
            totp_client.parse_config(config)

class TestParseConfigOther(unittest.TestCase):

    def get_config(self):
        return ConfigParser(defaults=totp_client.DEFAULTS)

    def test_empty(self):
        config = self.get_config()
        totps = totp_client.parse_config(config)
        self.assertEqual(0, len(totps))

    def test_period_60(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': b32encode(unhexlify('3132333435363738393031323334353637383930')).decode('utf-8'),
            'Period': '60'
        }
        totps = totp_client.parse_config(config)
        self.assertEqual(60, totps[0][1].period)

    def test_key_lowercase_spaces(self):
        config = self.get_config()
        config['key1'] = {
            'Secret': 'abcd efgh ijkl mnop qrst uvwx'
        }
        totps = totp_client.parse_config(config)
        self.assertEqual(1, len(totps))
    


if __name__ == '__main__':
    unittest.main()