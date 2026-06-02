# Release Infrastructure Setup

## APT Repository (hosted on GitHub Pages)

- [ ] 1. Create a `gh-pages` branch in the repo (empty branch is fine)
- [ ] 2. Enable GitHub Pages: repo Settings → Pages → Deploy from `gh-pages` branch
- [ ] 3. Generate a GPG signing key:
  ```bash
  gpg --full-generate-key
  gpg --armor --export-secret-key <key-id> | pbcopy  # macOS
  ```
- [ ] 4. Add repo secrets:
  - `APT_GPG_PRIVATE_KEY` — the exported private key
  - `APT_GPG_PASSPHRASE` — the key's passphrase
- [ ] 5. Update the URL in `.github/workflows/publish.yml` if your Pages URL is different from `chojuninengu.github.io/guardpost`

## Homebrew Tap

- [ ] 6. Create a repository named `homebrew-guardpost` under your GitHub account
- [ ] 7. Generate a Personal Access Token (PAT) with `repo` scope for that repo
- [ ] 8. Add repo secret `HOMEBREW_TAP_TOKEN` with the PAT value

## Chocolatey

- [ ] 9. Create an account at https://push.chocolatey.org
- [ ] 10. Generate an API key from your Chocolatey account page
- [ ] 11. Add repo secret `CHOCO_API_KEY` with the API key

## Release

- [ ] 12. Push a `v*` tag to trigger the release workflow
- [ ] 13. Publish the drafted release — this triggers the publish workflow above
