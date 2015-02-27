
Debian
====================
This directory contains files used to package ecashd/ecash-qt
for Debian-based Linux systems. If you compile ecashd/ecash-qt yourself, there are some useful files here.

## ecash: URI support ##


ecash-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install ecash-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your ecash-qt binary to `/usr/bin`
and the `../../share/pixmaps/ecash128.png` to `/usr/share/pixmaps`

ecash-qt.protocol (KDE)

