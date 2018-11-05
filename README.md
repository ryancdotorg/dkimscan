# dkimscan
A scanner for DKIM selectors.

This is some code I wrote in early 2012 that I realized I'd never gotten around
to releasing. An extensive list of common selectors and selector patterns is
built in. Please be aware that this sends a very high volume of queries and may
take several minutes to run a full scan.

If you're aware of any popular selector patterns that I missed but are feasibly searchable, please share.

#### What is it good for?

* Recon
  * Many email service providers and marketing companies have their customers add a predictable selector
  * Selector names and keys are sometimes reused across related domains

* Find weak keys - There are still domains out there with unused but still published 512 and 768 bit RSA keys
