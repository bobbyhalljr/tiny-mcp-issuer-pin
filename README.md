# tiny-mcp-issuer-pin

A tiny MCP client that pins its OAuth issuer, in one TypeScript file.
It connects two clients to one honest MCP server and three hostile ones, and logs every secret that leaves the machine.
The network, the login provider and the attacker are mocks. No API key.

## Why it matters

Patching the MCP SDK doesn't fix it.

On September 28, 2026, the MCP Python SDK published [GHSA-qx49-fqc8-xw99](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99) (High, 7.5).
A malicious MCP server could make the OAuth client send its client secret, authorization code and PKCE verifier to a token endpoint the server chose.
The fixed versions are `mcp` 1.30.0 and 2.2.0, but for the machine-to-machine providers the advisory says upgrading "changes nothing until you also pass `issuer=`."

The client has to know who it trusts before it asks.

## Run it

You need Node.js 18 or newer.

```bash
npm install
npx tsx issuer.ts
```

## Example output

This is real output from `npx tsx issuer.ts`:

```text
Credentials: acme-agent, pinned to auth.acme.example (MOCK network, no API key)

Server: honest server (mcp.acme.example)
  happy-path check  ok: token for mcp.acme.example
  pinned issuer     ok: token for mcp.acme.example

Server: 404 fallback (mcp.evil.example)
  happy-path check  LEAKED secret to mcp.evil.example
                      wire: client_secret + code + code_verifier -> mcp.evil.example
  pinned issuer     refused: no protected resource metadata

Server: names own server (mcp.evil.example)
  happy-path check  LEAKED secret to mcp.evil.example
                      wire: client_secret + code + code_verifier -> mcp.evil.example
  pinned issuer     refused: server wants mcp.evil.example, secret is pinned to auth.acme.example

Server: claims real resource (mcp.evil.example)
  happy-path check  LEAKED token for mcp.acme.example to mcp.evil.example
                      wire: bearer token (audience mcp.acme.example) -> mcp.evil.example
  pinned issuer     refused: resource mcp.acme.example is not mcp.evil.example

happy-path check  leaked to mcp.evil.example in 3 of 3 hostile runs
pinned issuer     leaked to mcp.evil.example in 0 of 3 hostile runs
```

The happy-path client leaked in 3 of 3 hostile runs. The pinned client refused all three and still connected to the honest server.

## How it works

```text
MCP server ──→ "log in over there"
                  ↓
Client ──→ is "over there" my pinned issuer?
                  ↓
Issuer ──→ metadata from the pinned origin only
                  ↓
Wire ──→ secret goes to one place, ever
```

| File | What it does |
| --- | --- |
| `issuer.ts` | The whole demo, in the same order as the post |
| `output.txt` | Real output of `npx tsx issuer.ts` |
| `package.json` | `tsx`, `typescript` and `@types/node` as dev dependencies |
| `tsconfig.json` | Strict settings for `npx tsc --noEmit` |

Inside `issuer.ts`:

- Types: `ResourceMetadata` (RFC 9728), `AuthServerMetadata` (RFC 8414), `Credentials`, `Token`
- `Network`: a MOCK network with one real login provider (`auth.acme.example`) and a hostile MCP server (`mcp.evil.example`) in three modes: `404 fallback`, `names own server`, `claims real resource`
- `happyPathClient`: checks the issuer only when it already learned one from resource metadata, and believes the `resource` field as-is. This is the shape of the bug class, not the SDK's code.
- `pinnedClient`: takes the expected issuer from config, refuses missing resource metadata, requires `resource` to match the server it connected to, requires the server to name the pinned issuer, and fetches login metadata only from the pinned issuer
- `wire`: every secret or token that left the client, and where it went

What is real and what is mocked:

- The network is a MOCK. No HTTP, no OAuth, no API key.
- Hostnames, client ids and secrets are example inputs.
- The hostile modes follow the bugs described in GHSA-qx49-fqc8-xw99 (Python SDK) and CVE-2026-63127 (rmcp, unchecked `resource`). This repo is not either SDK.

## Limits

This is a teaching client.

- Refusing on missing resource metadata breaks older servers. Allow them per server, in config, with the issuer pinned.
- A real client also checks `iss` on the authorization response (RFC 9207), binds tokens to the `resource` (RFC 8707) and tests the 403 step-up path.
- Stored registrations from before a fix carry no issuer. Clear them, and rotate secrets if a vulnerable client talked to a server you do not trust.

## Read more

- Dev.to: [Patching the MCP SDK Doesn't Fix It. Pin the OAuth Issuer in TypeScript.](https://dev.to/bobbyhalljr/patching-the-mcp-sdk-doesnt-fix-it-pin-the-oauth-issuer-in-typescript-2086)
- Substack: [Patching the MCP SDK Doesn't Fix It. Pin the OAuth Issuer in TypeScript.](https://bobbyhalljr.substack.com/p/patching-the-mcp-sdk-doesnt-fix-it)
- LinkedIn: [post](LINKEDIN_URL)
- Sources: [GHSA-qx49-fqc8-xw99](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99) (Sep 28, 2026), [Cycode write-up via The IT Nerd](https://itnerd.blog/2026/09/30/guest-post-cycode-uncovers-account-takeover-in-mcp-python-sdk/) (Sep 30, 2026), [WorkOS: Three MCP auth bugs in 30 days](https://workos.com/blog/mcp-auth-bugs-trusting-the-other-side) (Oct 2, 2026)

## License

MIT. See [LICENSE](LICENSE).
