# Sigstore Cert Watcher
Certificate monitor for the [Sigstore](https://www.sigstore.dev/) Transperency Leger.
```
$> ./sigstore-watcher
[ ] Start
[ ] Getting: 14047860 -> 14047860 (1)
{
  "GitHub Workflow Name": "Scorecards supply-chain security",
  "GitHub Workflow Ref": "refs/heads/main",
  "GitHub Workflow Repository": "youtube/cobalt_sandbox",
  "GitHub Workflow SHA": "8fc22e889672bd423063762415b2ff6990cf7d8f",
  "GitHub Workflow Trigger": "push",
  "Hash": "sha256:62def714d8272531e6bed311f80574420eadb5da8a5160c1c46ad03ac27e1fc3",
  "Log Index": 14047860,
  "OIDC Issuer": "https://token.actions.githubusercontent.com",
  "Subject": "https://github.com/youtube/cobalt_sandbox/.github/workflows/scorecards.yml@refs/heads/main"
}
```

# Overview
[Project Sigstore](https://www.sigstore.dev/) is a new project designed to make signing and verifying software easier and
more platform agnostic. [This blog from Trail of Bits](https://blog.trailofbits.com/2022/11/08/sigstore-code-signing-verification-software-supply-chain/)
explains it better than I can.

This project will continually poll Sigstore's immutable Transparency Leger, and print out the certificate details of any new software signed.
As well as alerting you to a new software being signed, these cetificates can contain some interesing information, such as:
 * OIDC Issuer
 * Signer username and hostname
 * Github repository, branch, and commit

# Build
```bash
git clone git@github.com:pathtofile/sigstore-watcher.git
cd sigstore-watcher
cargo build
# built binary should be at: ./target/debug/sigstore-watcher
```

# Running
```bash
cargo run
# Or run the binary directly
./target/debug/sigstore-watcher

# Specify a custom polling interal
cargo run -- --interval 10
./sigstore-watcher --interval 10
```

# Refrences
 * [How Sigstore Works](https://www.sigstore.dev/how-it-works)
 * [We sign code now](https://blog.trailofbits.com/2022/11/08/sigstore-code-signing-verification-software-supply-chain/)
 * [Log UI](https://rekor.tlog.dev/?logIndex=7180302)
 * [Parsing ASN-1 certificatges in Rust](https://users.rust-lang.org/t/comparison-of-way-too-many-rust-asn-1-der-libraries/58683/2)
