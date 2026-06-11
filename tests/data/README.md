# Vendored conformance corpus

`corpus.json` is extracted from the embedded `prop_*` unit tests of
[koalaman/shellcheck](https://github.com/koalaman/shellcheck)
(`src/ShellCheck/Analytics.hs` and `src/ShellCheck/Checks/Commands.hs`)
by `tools/extract_corpus.py`.

ShellCheck is licensed under the GNU General Public License v3. The test
snippets in this directory therefore remain under GPLv3. They are used only
as a development-time conformance corpus (run by pytest from the repository);
they are **not** included in the pureshellcheck wheel or any distributed
artifact, which are MIT-licensed.

Each entry:

- `id` — the original `prop_` name
- `check` — the ShellCheck check function the test targets
- `expect` — `trigger` (the check must fire) or `no-trigger` (it must not)
- `codes` — the SC codes that check function can emit
- `script` — the shell snippet, parsed as bash unless it has a shebang

To regenerate: `python tools/extract_corpus.py /path/to/shellcheck`.
