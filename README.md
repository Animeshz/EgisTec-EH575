# EgisTec EH575 Fingerprint Driver [Effort Archive]

This repository doesn't contain the driver, this is an archive of efforts made to enable this fingerprint sensor integrate with linux desktops. Final consideration is to integrate this with libfprint using `libfprint.patch` (with changes if applicable) as soon as [libfrpint#271](https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/271) [libfprint#272](https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/272) gets fixed.

The usb sequence has been found, inspect the libfprint.patch or the archive folder.


## Why archived?

I'm busy doing other things right now, and also I had been experiencing very unfortunate crashes on my last laptop (swift3 sf314-42) when running linux on it, namely [drm/amd#1829](https://gitlab.freedesktop.org/drm/amd/-/issues/1829). So I gave up and moved to framework laptop instead, I have given my laptop to my uncle which runs windows now, I do have access to it and 'M willing to provide any important assistance if required, also people in [#2](https://github.com/Animeshz/EgisTec-EH575/issues/2) will also be more pleasing in providing help in setting up and testing.


## Contents of repository

 * archive - A failed attempt to write both sensor driver and fingeprint matching algorithm (in rust, separate from libfprint because it wasn't able to process such small images 103x52 from sensor)
 * libfprint.patch - patch for the found sensor sequence to integrate on the libfprint itself, in regards that in future it'll be able process small fingerprint images (implemented as swipe sensor similar to EH750)
 * findings - Findings by trying to reverse engineering the driver or by watching the usb traffics


## Follow ups

 * Keep an eye on [#2](https://github.com/Animeshz/EgisTec-EH575/issues/2), people are sharing different details over there, I've also shared my findings and steps I found from trying to decypher the logic there. Some have also claimed to have made improvements over handling small images too, be sure to check out if it helps you too!
 * The two consecutive issues [libfrpint#271](https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/271) [libfprint#272](https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/272) at libfprint are for improvemnt over small resolution fingerprint image processing, keep an eye on them if you want to know when will it be possible for the small raw fingerprints to directly match.
 * EH570 driver which was merged initially, also showing the same behavior that it couldn't match quite easily due to small images, see [libfprint#418](https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/418).

