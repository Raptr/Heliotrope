# Heliotrope - Python binding for Libpurple

## What is Heliotrope?

Heliotrope is a client/server framework for driving Libpurple (the instant messaging engine behind the universal chat client, Pidgin).
It allows developers to quickly write custom IM applications in Python, without understanding all of the internals of Libpurple.

Heliotrope supports most of the IM features that one expects from an IM application (eg. sending/receiving messages, custom statuses,
multiple IM protocols, file transfers, etc...).  It does not yet support IRC, nor Audio/Video features.

## What platforms can Heliotrope run on?

Currently, Heliotrope runs on MS Windows XP, Vista and 7.  Support for Mac should be coming soon.  Patches to make it work on Linux
are welcome!

## How do I build Heliotrope?

You will need to following tools to build Heliotrope:

- libpurple [http//pidgin.im](http://pidgin.im)
- GNU C Compiler [http://gcc.gnu.org/](http://gcc.gnu.org/) and utilities
- Swig: [http://www.swig.org/](http://www.swig.org/)

On Windows, just setup a command prompt, adjust the paths in **Makefile.mingw** and issue:

	make -f Makefile.mingw

On Unix/Linux, use

	make -f Makefile.gmake

Windows users should use the Pidgin source code:
[http://pidgin.im/download/source/](http://pidgin.im/download/source/) and
MinGW build environment: [http://www.mingw.org/](http://www.mingw.org/).

Linux, BSD, and other *unix* users should obtain the associated development
packages for their distribution. Under Debian/Ubuntu will will need the '-dev'
packages, e.g. libpurple-dev. You will also require pkg-config.

## What is the meaning of "heliotrope"?

The Heliotrope project name came about as an alternative color to "purple". See: [http://en.wikipedia.org/wiki/Heliotrope_(color)][1]

## Can I contribute to Heliotrope?

Yes, by all means! If you find bugs or missing features, please join the project and submit patches!

[1]: http://en.wikipedia.org/wiki/Heliotrope_(color)
