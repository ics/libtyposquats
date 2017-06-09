Libtyposquats
=============

Typosquats check library
Python 3.6+ spin of `dnstwist <https://github.com/elceef/dnstwist>`_.


Usage
=====


.. code-block:: python

    >>> from urllib.parse import urlparse
    >>> from libtyposquats.typosquats import Typosquats
    >>> from libtyposquats.augment import Augmenter
    >>> from pprint import pprint
    >>> url = urlparse('http://europa.eu')
    >>> domains = Typosquats(url.netloc).generate()
    >>> checks = {'banners': True, 'whois': True, 'geoip': True}
    >>> augmenter = Augmenter(domains[56], url, **checks)
    >>> result = augmenter.augment()
    >>> pprint(result.__dict__)
    >>> {'dns_a': '46.28.105.3',
     'dns_aaaa': '2a02:2b88:1:4::17',
     'dns_ns': 'ns.wedos.com',
     'fuzzer': 'Homoglyph',
     'geoip_cc': 'CZ',
     'geoip_country': 'Czech Republic',
     'http_banner': 'Apache',
     'name': 'eur0pa.eu',
     'whois_created': 'None',
     'whois_updated': 'None'}


.. code-block:: bash

    ./domainfuzzer --help
    usage: domainfuzzer [-h] [-c | -j] [-r] [-w] [-g] [-b] [-s] [-m] [-d FILE]
                   [-t NUMBER] [-u USERAGENT] [-v]
                   domain

    Detect possible typosquatters, phishing attacks, etc.

    positional arguments:
      domain                domain name or URL to check

    optional arguments:
      -h, --help            show this help message and exit
      -c, --csv             output in CSV format
      -j, --json            output in JSON format
      -r, --registered      show only registered domain names
      -w, --whois           perform whois lookup
      -g, --geoip           perform lookup for GeoIP location
      -b, --banners         determine HTTP and SMTP service banners
      -s, --ssdeep          fetch web pages and compare their fuzzy hashes to
                            evaluate similarity
      -m, --mxcheck         check if MX host can be used to intercept e-mails
      -d FILE, --dictionary FILE
                            generate additional domains using dictionary FILE
      -t NUMBER, --workers NUMBER
                            start at most NUMBER of workers (default: 8)
      -u USERAGENT, --useragent USERAGENT
                            User-agent to use for HTTP requests
      -v, --verbose
