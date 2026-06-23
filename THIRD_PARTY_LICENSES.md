# Third-Party Licenses

Agent Wallet is distributed under the [MIT License](LICENSE). This file lists
the third-party components that are **vendored** (bundled directly in this
repository) and their licenses.

The vendored frontend libraries live in
`app/dashboard/static/vendor/`. They are served by the dashboard as-is.

The Python, Rust, and Node.js dependencies are **not** vendored — they are
declared in `pyproject.toml`, `Cargo.toml` / `Cargo.lock`, and the `scripts/`
`package.json` and resolved at install/build time. Those dependencies are all
permissively licensed (predominantly MIT, BSD, and Apache-2.0). Consult each
package's own distribution for its exact license text.

## Vendored frontend libraries

| Library | File | License | Copyright |
|---|---|---|---|
| Alpine.js (CSP build) | `app/dashboard/static/vendor/alpinejs-csp-3.15.11.min.js` | MIT | Copyright (c) Caleb Porzio and contributors |
| qrcode (qrcodejs) | `app/dashboard/static/vendor/qrcode-1.4.4.min.js` | MIT | Copyright (c) davidshimjs (qrcodejs) |
| Lucide | `app/dashboard/static/vendor/lucide-0.469.0.min.js` | ISC | Copyright (c) Lucide Contributors |

The bundled `lucide-0.469.0.min.js` retains its in-file `@license` banner; that
banner is part of the distributed source and must be kept intact.

---

## MIT License

Applies to **Alpine.js** and **qrcode** as listed above.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ISC License

Applies to **Lucide** as listed above.

```
ISC License

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
```
