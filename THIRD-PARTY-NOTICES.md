# Third-party notices

## Detect It Easy

The signature database `src/main/resources/data/signatures/die.sig` contains
signatures converted from the PE detection rules of
[Detect It Easy](https://github.com/horsicq/Detect-It-Easy) by hors, folder
`db/PE` at commit `c9f58b9b8d1bd251c99e60565246092ff6920b1f`. The rules were
translated to the PortEx signature format, see
[docs/SIGNATURES.md](docs/SIGNATURES.md#signatures-from-detect-it-easy). Each
entry names the authors of its rule in the key `author` and the source file in
the key `url`.

Authors of the converted rules: horsicq, hypn0, DosX, ajax, BJNFNE, A.S.L,
Jason Hood (adoxa), deadmau5, Nitr0-G, 0x80000003, KDSS-Research, Levis,
sendersu, ELF_7719116, Yosef Khaled, Eliseu Filipi, r0da, Arjan Onwezen,
@justmazz_, securitystar, Vito, LinXP.

Only the reviewed main database `db/PE` was used, not `db_extra`, the YARA
rules or the PEiD databases of the repository.

```
MIT License

Copyright (c) 2012-2026 hors<horsicq@gmail.com>

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
