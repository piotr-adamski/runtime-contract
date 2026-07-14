# GitHub Action release and Marketplace checklist

The root composite Action and the Python package share this repository but have separate version
roles. An immutable Action tag identifies the adapter source. The Action's `version` input identifies
the exact released package installed from PyPI. The default package version may remain unchanged for
an adapter-only patch release when compatibility tests prove that exact package release.

## Automated release gates

Before creating or moving any Action tag:

1. Merge through the repository's rebase-only pull-request policy.
2. Record the final `main` commit SHA.
3. Require exact-`main` CI, Policy, Security, and CodeQL runs to succeed for that SHA.
4. Confirm the default `version` in `action.yml` exists on public PyPI and is not yanked.
5. Confirm the Action E2E installed that PyPI version rather than the local checkout.
6. Validate all README links and every `uses:` reference; external Actions must use full SHAs.
7. Run the five-minute adoption workflow from a clean consumer repository or isolated checkout.
8. Create a new signed immutable semver tag, for example `v0.1.1`, at the verified `main` SHA.
9. Move the unsigned compatibility tag `v0` to that same SHA only after the immutable tag and
   public `uses: owner/repository@<immutable-tag>` test succeed.

Never move an existing immutable tag, create `latest`, or move `v0` before the release gates pass.
Consumers with strict supply-chain policy should use the full commit SHA rather than `v0`.

## Manual Marketplace publication

GitHub Marketplace publication is an owner action in the GitHub web interface; adding `action.yml`
does not publish a listing. The repository owner must:

1. Open the root `action.yml` on GitHub and choose **Draft a release**.
2. Accept the GitHub Marketplace Developer Agreement if GitHub requests it.
3. Select **Publish this Action to the GitHub Marketplace**.
4. Resolve any metadata validation warning and confirm that the Action name is available.
5. Select the most accurate primary category, use the already verified immutable Action tag, and
   publish with two-factor authentication.
6. Open the resulting Marketplace listing and run its copied `uses:` snippet in a clean repository.

The automated release report must leave Marketplace as `MANUAL_OWNER_STEP` until the listing URL
and the owner-confirmed publication are observable. Marketplace availability is a distribution
channel and must not be reported as product adoption.

## Rollback

Do not rewrite an immutable tag. If an Action release is defective, document the affected tag,
publish a fixed patch tag from a green exact-`main` commit, verify it publicly, and only then move
`v0` to the fixed commit. Existing full-SHA and immutable-tag consumers remain reproducible.
