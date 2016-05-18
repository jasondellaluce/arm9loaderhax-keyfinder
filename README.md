# Arm9LoaderHax Bruteforce Key Finder
### Copyright (C) 2016 Jason Dellaluce

This is a cleaned-up version of the tool i used to find the proper key in [my implementation](https://github.com/delebile/arm9loaderhax) of the arm9loaderhax exploit.

In order to build it you need GCC or MinGW, nothing more should be requested.

Just drag and drop a N3DS FIRM of version 9.6 or more, and then wait for random keys to be tested, it will print them in the screen if they are exploitable.

Current speed: ~250 attempts/min (TODO : improve speed)


Also, this includes my C reproduction of the 3DS AES Engine, feel free to take inspiration and improve it for other PC tools, but remember to credit it.
