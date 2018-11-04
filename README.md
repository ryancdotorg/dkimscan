# dkimscan
A scanner for DKIM selectors.

This is some code I wrote in early 2012 that I realized I'd never gotten around
to releasing. An extensive list of common selectors and selector patterns is
built in. Please be aware that this sends a very high volume of queries and may
take several minutes to run a full scan.

#### What is it good for?

* Recon - many email service providers and marketing companies have their customers add a predictable selector

* Find weak keys - There are still domains out there with unused but still published 512 and 768 bit RSA keys
