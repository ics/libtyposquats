import os
import sys
import csv
import json
import logging
import asyncio
import argparse
from urllib import request
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import ssdeep
from libtyposquats.typosquats import Typosquats, sorted_attrs
from libtyposquats.augment import Augmenter

try:
    import uvloop
    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
except ImportError:
    loop = asyncio.get_event_loop()


log = logging.getLogger('libtyposquats')
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


def generate_csv(domains):
    yield ([k for k, v in sorted_attrs(domains[0])])
    for domain in domains:
        yield([v or '' for k, v in sorted_attrs(domain)])


async def supervisor(url, **kwargs):
    results = await find_typosquats(url, **kwargs)
    return results


async def find_typosquats(url, **kwargs):
    dict_ = kwargs.get('dictionary', None)
    ua = kwargs.get('useragent', None)

    original_ctph = await loop.run_in_executor(None, _calc_ctph, url, ua)
    log.debug(f'CTPH of original URL is: {original_ctph}')

    # typosquats = await tq.generate(**kwargs)
    tq = Typosquats(domain=url.netloc)
    typosquats = await loop.run_in_executor(None, tq.generate, dict_)
    log.info(f'Generated {len(typosquats)} typosquats')

    tasks = [run_augmenter(t, url, **kwargs) for t in typosquats]

    results = await asyncio.gather(*tasks)
    return results


async def run_augmenter(typosquat, url, **kwags):
    log.debug(f'{typosquat.name}: starting augmenter ***')
    result = await loop.run_in_executor(
            None, augment_sync, typosquat,
            url, kwags)
    return result


def augment_sync(typosquat, original, kwargs):
    augmenter = Augmenter(typosquat, original, **kwargs)
    return augmenter.augment()


def _calc_ctph(url, useragent):
    req = request.Request(url.geturl())
    req.add_header('User-Agent', useragent)
    resp = request.urlopen(req, timeout=5)
    original_ctph = ssdeep.hash(resp.read().decode())
    return original_ctph


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        add_help=True,
        description='Detect possible typosquatters, phishing attacks, etc.')

    parser.add_argument('domain', help='domain name or URL to check')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-c', '--csv', action='store_true',
                       help='output in CSV format')
    group.add_argument('-j', '--json', action='store_true',
                       help='output in JSON format')
    parser.add_argument('-r', '--registered', action='store_true',
                        help='show only registered domain names')
    parser.add_argument('-w', '--whois', action='store_true',
                        help='perform whois lookup')
    parser.add_argument('-g', '--geoip', action='store_true',
                        help='perform lookup for GeoIP location')
    parser.add_argument('-b', '--banners', action='store_true',
                        help='determine HTTP and SMTP service banners')
    parser.add_argument('-s', '--ssdeep', action='store_true',
                        help='fetch web pages and compare their fuzzy hashes '
                             'to evaluate similarity')
    parser.add_argument('-m', '--mxcheck', action='store_true',
                        help='check if MX host can be used to intercept '
                             'e-mails')
    parser.add_argument('-d', '--dictionary', type=str, metavar='FILE',
                        help='generate additional domains using dictionary '
                             'FILE')
    parser.add_argument('-t', '--workers', type=int, metavar='NUMBER',
                        default=os.cpu_count(),
                        help='start at most NUMBER of workers (default: {})'.
                        format(os.cpu_count()))
    parser.add_argument('-u', '--useragent', type=str,
                        default='Mozilla/5.0',
                        help="User-agent to use for HTTP requests")
    parser.add_argument('-v', '--verbose', action='store_const',
                        dest='loglevel', const=logging.DEBUG,
                        default=logging.WARNING)

    return parser.parse_args(argv[1:])


def main(argv=None):
    if argv is None:
        argv = sys.argv
    args = _parse_args(argv)
    log.setLevel(args.loglevel)

    if '://' not in args.domain:
        # no scheme, assuming http
        args.domain = 'http://' + args.domain

    url = urlparse(args.domain)
    del args.domain

    executor = ThreadPoolExecutor(max_workers=args.workers)
    loop.set_default_executor(executor)

    try:
        results = loop.run_until_complete(supervisor(url, **vars(args)))
    except KeyboardInterrupt:
        loop.stop()
    finally:
        executor.shutdown()
        loop.close()

    log.info('[*] Done! Generating output...')
    if args.csv:
        log.info('[*] Outputting CSV...')
        out = csv.writer(sys.stdout)
        out.writerows(generate_csv(results))
    elif args.json:
        log.info('[*] Outputting JSON ...')
        sys.stdout.write(json.dumps([r.__dict__ for r in results],
                                    sort_keys=True))
    else:
        row_fmt = "{:<15}{:<40}{:<16}{:<5}{}"
        header = ['Algorithm', 'Domain', 'A', 'CC', 'NS']
        print('\033[1m', row_fmt.format(*header))
        print('=' * 80, '\033[0m')
        for d in results:
            print(row_fmt.format(d.fuzzer, d.name, str(d.dns_a),
                                 str(d.geoip_cc), str(d.dns_ns)))


if __name__ == '__main__':
    sys.exit(main())
