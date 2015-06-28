[![Build Status](https://travis-ci.org/digitalbitbox/bitbox-client.svg?branch=master)](https://travis-ci.org/digitalbitbox/bitbox-client)
[![License](http://img.shields.io/:License-MIT-yellow.svg)](LICENSE)


C client library for the [Digital Bitbox](https://digitalbitbox.com) hardware wallet.

The communication protocol is desribed in the [API](https://digitalbitbox.com/api.html).


### Contributing

Please do *NOT* use an editor that automatically reformats.

Use the coding style set by astyle (http://astyle.sourceforge.net/) with the following parameteres:
> astyle --style=stroustrup --indent-switches --indent-labels --pad-oper --pad-header --align-pointer=name --add-brackets --convert-tabs --max-code-length=90 --break-after-logical --suffix=none *.c *.h --recursive
