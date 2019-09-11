# totp_client

`totp_client` is a minimal Python 3 command line tool for generating Multi-Factor Authentication (MFA) codes using the Time-Based One-Time Password (TOTP) algorithm as described in RFC 6238 and RFC 4226. It can be used for testing TOTP implementations or for personal use (similar to Google Authenticator), _provided you take the appropriate measures to secure access_.

## Examples

### Continuously Display OTPs
```
$ sudo python3 totp_client.py 
AWS root account       815367     11/30 s.
AWS IAM user Naveen    743139     11/30 s.
```

This displays OTPs continuously for all keys configured in the default config file, `~/.totp.cfg`, for a default period of 30 seconds and exits.

### Show Current OTP for Specific Key in Specific Config File
```
$ sudo python3 totp_client.py -c totp.cfg -n 'AWS IAM' -t 0
AWS IAM user Naveen    057415      7/30 s.
```

This displays the current OTP value for the key starting with 'AWS IAM' coming from the config file `totp.cfg` in the current directory.

### Dump OTPs
```
$ sudo python3 totp_client.py --dump
-10     2019-06-18 14:53:30     AWS root account        731847
-10     2019-06-18 14:53:30     AWS IAM user Naveen     912137
-9      2019-06-18 14:54:00     AWS root account        236069
-9      2019-06-18 14:54:00     AWS IAM user Naveen     753752
-8      2019-06-18 14:54:30     AWS root account        850918
-8      2019-06-18 14:54:30     AWS IAM user Naveen     057415
-7      2019-06-18 14:55:00     AWS root account        837553
-7      2019-06-18 14:55:00     AWS IAM user Naveen     006676
-6      2019-06-18 14:55:30     AWS root account        730314
-6      2019-06-18 14:55:30     AWS IAM user Naveen     185953
-5      2019-06-18 14:56:00     AWS root account        035809
-5      2019-06-18 14:56:00     AWS IAM user Naveen     998820
-4      2019-06-18 14:56:30     AWS root account        177180
-4      2019-06-18 14:56:30     AWS IAM user Naveen     136046
-3      2019-06-18 14:57:00     AWS root account        729959
-3      2019-06-18 14:57:00     AWS IAM user Naveen     043860
-2      2019-06-18 14:57:30     AWS root account        503288
-2      2019-06-18 14:57:30     AWS IAM user Naveen     661158
-1      2019-06-18 14:58:00     AWS root account        676262
-1      2019-06-18 14:58:00     AWS IAM user Naveen     907533
0       2019-06-18 14:58:30     AWS root account        191744
0       2019-06-18 14:58:30     AWS IAM user Naveen     141046
1       2019-06-18 14:59:00     AWS root account        532647
1       2019-06-18 14:59:00     AWS IAM user Naveen     716455
2       2019-06-18 14:59:30     AWS root account        764287
2       2019-06-18 14:59:30     AWS IAM user Naveen     155415
3       2019-06-18 15:00:00     AWS root account        142524
3       2019-06-18 15:00:00     AWS IAM user Naveen     992052
4       2019-06-18 15:00:30     AWS root account        812688
4       2019-06-18 15:00:30     AWS IAM user Naveen     240848
5       2019-06-18 15:01:00     AWS root account        198451
5       2019-06-18 15:01:00     AWS IAM user Naveen     670004
6       2019-06-18 15:01:30     AWS root account        120146
6       2019-06-18 15:01:30     AWS IAM user Naveen     151637
7       2019-06-18 15:02:00     AWS root account        918635
7       2019-06-18 15:02:00     AWS IAM user Naveen     181147
8       2019-06-18 15:02:30     AWS root account        401737
8       2019-06-18 15:02:30     AWS IAM user Naveen     155137
9       2019-06-18 15:03:00     AWS root account        009702
9       2019-06-18 15:03:00     AWS IAM user Naveen     700472
10      2019-06-18 15:03:30     AWS root account        588283
10      2019-06-18 15:03:30     AWS IAM user Naveen     593703
```

This dumps out all OTPs for all configured keys spanning a 10 periods prior to the current time and 10 periods after the current time. 10 periods translates to 5 minutes for OTPs with a period of 30 seconds.

### Dump OTPs for a Specific Key Over a Defined Interval
```
$ sudo python3 totp_client.py --dump --dump_start -5 --dump_end 5 -n 'AWS IAM'
-5      2019-06-18 14:59:30     AWS IAM user Naveen     155415
-4      2019-06-18 15:00:00     AWS IAM user Naveen     992052
-3      2019-06-18 15:00:30     AWS IAM user Naveen     240848
-2      2019-06-18 15:01:00     AWS IAM user Naveen     670004
-1      2019-06-18 15:01:30     AWS IAM user Naveen     151637
0       2019-06-18 15:02:00     AWS IAM user Naveen     181147
1       2019-06-18 15:02:30     AWS IAM user Naveen     155137
2       2019-06-18 15:03:00     AWS IAM user Naveen     700472
3       2019-06-18 15:03:30     AWS IAM user Naveen     593703
4       2019-06-18 15:04:00     AWS IAM user Naveen     091770
5       2019-06-18 15:04:30     AWS IAM user Naveen     830154
```

This dumps out OTPs for a specific key starting with 'AWS IAM' over a custom interval: 5 periods before and 5 periods after the current time. 5 periods translates to 2 minutes and 30 seconds for OTPs with a period of 30 seconds.

## Configuration

By default `totp_client` looks for a config file located at `~/.totp.cfg`. You can set up the config file at a different location and point the tool to it using the `-c` flag.

The config file format mimics the structure of Windows INI files. Each section of the config file corresponds to a TOTP key, with the name of the section representing the name of the TOTP key. At a minimum, in each section, the `Secret` parameter is required, in Base32-encoded format. For instance:

```
[My TOTP Key 1]
Secret = MYBASE32ENCODEDSECRET1
```

By default, the other TOTP parameters are defaulted as follows:

```
Digits = 6
Algorithm = sha1
Period = 30
```

This matches the common default used by many applications. You can explicitly override these parameters for your key if needed. For instance:

```
[My TOTP Key 2]
Secret = MYBASE32ENCODEDSECRET2
Digits = 8
Algorithm = sha256
Period = 60
```

Supported configuration values are:

```
Digits: 6, 7, 8, or 9
Algorithm: sha1, sha256, or sha512
Period: 30 or 60
```

## Security

If using for personal use, make sure you know what you're doing. If the config file is exposed, secrets in the config file can be used to directly generate MFA codes and bypass MFA altogether. Secrets in the config file are not encrypted.

One option in Unix-like environments is to use `chown` and `chmod` to restrict config file access to a superuser. Then run `totp_client.py` with elevated privileges using a tool like `sudo` or `su`. This provides an extra degree of protection because it will require you to re-enter your credentials or superuser credentials before invoking the tool.

Alternatively, you can put `totp_client` on another secured machine on the network and write a script to ssh into that machine to invoke the tool. Something like:

```
#!/bin/bash

ssh <user>@<your machine> python3 totp_client.py
```

It's up to you to make the right trade off between security and convenience.

By default, the tool runs for 30 seconds before exiting to protect against inadvertently keeping the tool open. The time the tool runs can be adjusted using the `-t` flag.

## Tests

`totp_client` has been tested on macOs and Linux with Python 3.5+. No external modules are required.

Unit tests can be run as follows:

```
$ python3 -m unittest test_totp_client.py 
..................
----------------------------------------------------------------------
Ran 18 tests in 0.006s

OK
```

## Full Usage

```
$ sudo python3 totp_client.py -h
usage: totp_client.py [-h] [-c CONFIG] [-t TIME] [-n NAME] [-d]
                      [-ds DUMP_START] [-de DUMP_END]

Print out Multi-Factor Authentication (MFA) codes using the Time-Based One-Time Password (TOTP) algorithm.
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

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to config file containing one or more TOTP keys.
                        Default location is ~/.totp.cfg.
  -t TIME, --time TIME  How long to run the tool in seconds before the tool
                        exits. Set this to 0 to have the tool print out
                        current OTP values and exit immediately. Default is 30
                        seconds.
  -n NAME, --name NAME  Only show keys whose names start with the given name.
                        Default is to show all keys.
  -d, --dump            Enables dump mode, which causes the tool to prints out
                        OTP codes in a tab-delimited format in an interval
                        defined by the dump_start and dump_end parameters and
                        then exit.
  -ds DUMP_START, --dump_start DUMP_START
                        period number to start dump from, relative to current
                        period of 0. The default is -10, i.e. 5 minutes before
                        now for a period of 30 seconds.
  -de DUMP_END, --dump_end DUMP_END
                        period number to end dump at, relative to current
                        period of 0. The default is 10, i.e. 5 minutes from
                        now for a period of 30 seconds.
```

## License

Copyright 2019 Naveen Sunkavally

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

