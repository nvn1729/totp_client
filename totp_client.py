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

"""Prints out Multi-Factor Authentication (MFA) codes using the Time-Based One-Time Password (TOTP) algorithm, as described in RFC 6238 and RFC 4226."""

import hmac, hashlib, time, sys, os
from base64 import b32decode
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from datetime import datetime
from math import floor
from configparser import SafeConfigParser, MissingSectionHeaderError

TOOL_DESCRIPTION = """Print out Multi-Factor Authentication (MFA) codes using the Time-Based One-Time Password (TOTP) algorithm.
The TOTP algorithm is described in RFC 6238 and RFC 4226.

By default the tool looks for a config file located at ~/.totp.cfg. It continuously displays OTPs for 30 seconds and exits.

In 'dump' mode, the tool can dump OTP codes over a range of OTP periods.

The config file is structured in a format similar to the Windows INI format.
For example:

[My TOTP Key 1]
Secret = MYBASE32ENCODEDSECRET1

[My TOTP Key 2]
Secret = MYBASE32ENCODEDSECRET2
Digits = 8
Algorithm = sha256
Period = 60

The following TOTP parameters are supported:
                          
Secret: A Base32-encoded secret. This is required.
Digits: Number of OTP digits. Default is 6.
Algorithm: The HMAC hashing algorithm used to generate OTPs. Default is sha1.
Period: Number of seconds before the OTP expires. Default is 30 seconds.

** Take care to secure the config file appropriately. **

For instance, in UNIX-like environments, consider using chown/chmod to restrict config file ownership and access to a superuser.
Then run this script with elevated privileges.
"""

DEFAULTS = {
    'Digits': '6',
    'Period': '30',
    'Algorithm': 'sha1'
}

ALGORITHMS = {
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512
}

DIGITS = [10**i for i in range(0, 10)]

# Terminal control characters
TERM_OTP_COLOR_NORMAL = "\u001b[34;1m" # bright blue
TERM_OTP_COLOR_WARN = "\u001b[31;1m"   # bright red
TERM_RESET = "\u001b[0m"               # reset
TERM_MOVE_LEFT = "\u001b[1000D"        # move cursor left
TERM_MOVE_UP = "\u001b[{}A"            # move cursor up with format parameter for number of lines to move up


class Hotp:
    """Implementation of the HOTP algorithm in accordance with RFC 4226.

       Construct a Hotp class using the Hotp parameters (secret, hash algorithm, and number of code digits).
       Call the at() method with the counter to get the OTP.
    """

    def __init__(self, secret, digestmod=hashlib.sha1, digits=6):
        self._secret = secret
        self._digestmod = digestmod
        self._digits = digits
        self._modulus = DIGITS[digits]

    def at(self, counter):
        """Compute and return the HOTP OTP value using the provided counter."""

        # Step 1: Compute HMAC using the secret, counter as message, and hashing algorithm
        d = hmac.new(self._secret, msg=counter, digestmod=self._digestmod).digest()

        # Step 2: Use the last 4 bits of the computed mac as an offset into the mac
        offset = d[-1] & 0x0F

        # Step 3: Use the offset to select 31 consecutive bits from the mac and represent those bits as an int
        v = int.from_bytes([ d[offset] & 0x7F, d[offset+1], d[offset+2], d[offset+3] ],
                            byteorder='big')
        
        # Step 4: Truncate the integer using the modulus, which is based on the number of OTP digits.
        #         Represent the result as a string and zero-pad in front if required.
        val = str(v % self._modulus)
        val = (self._digits-len(val))*'0' + val

        return val


class Totp:
    """Implementation of the TOTP algorithm, in accordance with RFC 6238.
    
       Construct a Totp class using the Hotp parameters plus a period parameter.
       The period determines the frequency at which the HOTP counter is incremented.
    """ 

    def __init__(self, secret, digestmod=hashlib.sha1, digits=6, period=30):
        self._hotp = Hotp(secret, digestmod=digestmod, digits=digits)
        self._period = period

    @property
    def period(self):
        return self._period

    def now(self):
        """Compute TOTP using current time in Unix seconds since the epoch
        
           Returns: a tuple of (current OTP, remaining seconds left before OTP expires, current time)
        """

        t = time.time()
        return self.at(floor(t))

    def at(self, t):
        """Compute TOTP at designated time, where time is represented as Unix seconds since the epoch
           
           Returns: a tuple of (OTP at time, remaining seconds left before OTP expires, time)
        """

        # Step 1: Compute the HOTP counter by dividing the time by the number of periods and taking the floor.
        counter = t // self._period
        remaining = (self._period - (t % self._period))

        # Step 2: Convert counter to 8 byte array
        counter_bytes = counter.to_bytes(8, byteorder='big')

        # Step 3: Compute OTP using counter
        return (self._hotp.at(counter_bytes), remaining, t)


def run(totps, time_to_run):
    """ Prints current OTP values for given keys continuously until time_to_run has expired"""

    # get the max key length to format for equal width when printing to terminal
    max_key_len = max([len(key_name) for key_name, _ in totps])

    # counter for number of OTP updates to print to screen, goes til time_to_run
    loops = 0

    # reserve space in terminal window for the number of lines equal to the number of TOTP keys
    sys.stdout.write('\n' * len(totps))

    while True:
        # move back to original terminal position before starting to print OTPs
        sys.stdout.write("{}{}".format(TERM_MOVE_LEFT, TERM_MOVE_UP.format(len(totps))))

        # for each OTP
        for key_name, totp in totps:

            # get current OTP value and time remaining before OTP expires
            otp, remaining, _ = totp.now()

            key_name_padded = key_name + (' ')*(max_key_len-len(key_name)+3)
            period = totp.period

            # print out line in the format: <key name> <OTP value> <elapsed time/period>
            # the OTP value is colored red if it's close to expiring (within 5 seconds of expiry)
            sys.stdout.write("{0} {1}{2:10}{3} {4:2}/{5:2} s.\n".format(
                key_name_padded,
                (TERM_OTP_COLOR_WARN if remaining <= 5 else TERM_OTP_COLOR_NORMAL),
                otp,
                TERM_RESET,
                (period-remaining),
                period))

        sys.stdout.flush()

        if loops >= time_to_run:
            break
        else:
            # wait 1 second between updates
            loops += 1
            time.sleep(1)


def dump(totps, dump_start, dump_end):
    """Dump out all OTPs over range [dump_start, dump_end] in tab-delimited format"""

    # get current time in Unix seconds since the epoch
    t = floor(time.time())

    # for each period and each key
    for i in range(dump_start, dump_end+1):
        for key_name, totp in totps:

            # get the otp value for that instant in time, relative to the current time
            otp, remaining, timestamp = totp.at(t + i*totp.period)

            # adjust the timestamp to reflect the beginning of the period when the OTP value is valid
            adj_timestamp = timestamp - (totp.period - remaining)

            # print out in tab delimited format: <period number> <adjusted timestamp> <key name> <otp>
            sys.stdout.write("{0}\t{1}\t{2}\t{3}\n".format(
                i, 
                str(datetime.fromtimestamp(adj_timestamp)),
                key_name,
                otp))

    sys.stdout.flush()


def read_config(config_file):
    """Get ConfigParser object from input config_file. Raise an exception if file is invalid, not found, inaccessible"""

    config = SafeConfigParser(defaults=DEFAULTS)
    try:
        files_read = config.read(config_file)
    except MissingSectionHeaderError:
        raise Exception('Config file {} appears to be empty or misconfigured'.format(config_file))
    
    if config_file not in files_read:
        raise Exception('Config file {} not found'.format(config_file))

    return config


def parse_config(config):
    """Extract the properties from the input ConfigParser object and return a list of Totp instances.

       Return value is a list of the tuples, with each tuple of the format (<key name>, <totp instance>).
       Raises an exception if the config is invalid. 
    """

    totps = []
    
    for key_name in config.sections():
        
        try:
            digits = config.getint(key_name, 'Digits')
        except:
            raise Exception('Digits value is not numeric for key {}'.format(key_name))

        try:
            period = config.getint(key_name, 'Period')
        except:
            raise Exception('Period value is not numeric for key {}'.format(key_name))

        try:
            # keys can be lower case and have spaces in them
            secret = b32decode(config.get(key_name, 'Secret').upper().replace(" ", ""))
        except:
            raise Exception('Missing or invalid Secret for key {}'.format(key_name))
            
        algorithm = config.get(key_name, 'Algorithm').lower()

        if digits < 6 or digits > 9:
            raise Exception('Digits must be between 6 and 9 for key {}'.format(key_name))

        if not (algorithm in ALGORITHMS):
            raise Exception('Algorithm must be one of {} for key {}'.format(list(ALGORITHMS.keys()), key_name))

        if not (period == 30 or period == 60):
            raise Exception('Period must be either 30 or 60 for key {}'.format(key_name))

        totp = Totp(secret, digits=digits, period=period, digestmod=ALGORITHMS[algorithm])

        totps.append( (key_name, totp) )

    return totps


def get_parser():
    """Return an ArgumentParser instance configured for this tool"""

    parser = ArgumentParser(description=TOOL_DESCRIPTION, formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-c', '--config', help='Path to config file containing one or more TOTP keys. Default location is ~/.totp.cfg.', default='~/.totp.cfg')
    parser.add_argument('-t', '--time', type=int, help='How long to run the tool in seconds before the tool exits. Set this to 0 to have the tool print out current OTP values and exit immediately. Default is 30 seconds.', default=30)
    parser.add_argument('-n', '--name', help='Only show keys whose names start with the given name. Default is to show all keys.')
    parser.add_argument('-d', '--dump', action='store_true', help='Enables dump mode, which causes the tool to prints out OTP codes in a tab-delimited format in an interval defined by the dump_start and dump_end parameters and then exit.')
    parser.add_argument('-ds', '--dump_start', type=int, help='period number to start dump from, relative to current period of 0. The default is -10, i.e. 5 minutes before now for a period of 30 seconds.', default=-10)
    parser.add_argument('-de', '--dump_end', type=int, help='period number to end dump at, relative to current period of 0. The default is 10, i.e. 5 minutes from now for a period of 30 seconds.', default=10)

    return parser
    
        
def main():
    """Entry point for the totp_client tool"""

    # parse tool arguments
    args = get_parser().parse_args()

    # parse totp config file
    try:
        totps = parse_config(read_config(os.path.expanduser(args.config)))
    except Exception as e:
        sys.stderr.write('Config file {} missing, inaccessible, or invalid: {}\n'.format(args.config, e))
        sys.exit(1)

    # exit if there are no keys configured
    if len(totps) == 0:
        sys.stderr.write('No keys configured in config file {}\n'.format(args.config))
        sys.exit(1)

    # filter totps list by 'name' if 'name' argument is set
    if args.name is not None:
        totps = [ (key_name, totp) for key_name, totp in totps if key_name.startswith(args.name.strip()) ]
        if len(totps) == 0:
            sys.stderr.write('No keys matching name filter {}\n'.format(args.name.strip()))
            sys.exit(1)

    try:
        # in dump, print out totps over dump interval and exit
        if args.dump:
            if args.dump_start > args.dump_end:
                sys.stdout.write('dump_start ({}) should be less than or equal to dump_end ({})\n'.format(args.dump_start, args.dump_end))
                sys.exit(1)
            dump(totps, args.dump_start, args.dump_end)

        # in 'normal' mode, print totps continuously until args.time time has elapsed
        else:
            if args.time < 0:
                sys.stdout.write('time ({}) should be at least 0\n'.format(time))
                sys.exit(1)
            run(totps, args.time)
    
    except KeyboardInterrupt:
        # ignore ctrl-c exit
        sys.exit(0)

    except Exception as e:
        sys.stderr.write('Unexpected error {}\n'.format(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
