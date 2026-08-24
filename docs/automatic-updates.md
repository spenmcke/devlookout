# Automatic Linux updates

Lookout Linux installations use a root-owned systemd oneshot service and timer. The timer polls the stable channel every minute with up to 30 seconds of randomized delay. HTTP ETags avoid downloading unchanged manifests, and failures use exponential backoff capped at one hour.

The updater accepts only strictly validated manifests signed by a pinned Ed25519 key. It rejects sequence replay and equivocation, downloads the artifact for the VM architecture, verifies its signed size and SHA-256 digest, and checks the release layout before activation. New releases must remain compatible with the currently running central and collector protocol during a rolling update.

Activation uses an atomic `current` symlink swap. The updater restarts the active Lookout services and checks their systemd health. A failed check restores the previous release and services. Only the active and previous application releases, plus the active updater release, are retained.

## Publishing

1. Merge the release commit to `main`.
2. Create the versioned, GitHub-verified signed tag. The Release workflow tests the commit, builds amd64 and arm64 artifacts with the pinned runtime, attests them, and creates the GitHub release.
3. Manually run `Publish signed stable update` from `main`. Supply the release tag, a sequence higher than every prior publication, and the `install` action.
4. The production environment signs the manifest with its scoped secret and publishes it to the stable channel table. The signing private key is never stored in the repository or SaaS runtime.

Use `pause` with a higher sequence to stop installations without disabling polling. Use `rollback` with a higher sequence and an older release tag to force an atomic application rollback. A forced rollback keeps the newer updater selected.

For signing-key rotation, first publish a release whose `config/update-signing-public-keys.json` contains both old and new public keys. After that release is installed, sign with the new key. A later signed release may remove the old public key.

Installations made before the updater existed cannot grant a new root service to themselves. Stage a current verified release on each such VM and run `sudo LOOKOUT_SOURCE_DIR=/path/to/release install/seed-updater.sh` once. New installations enable the timer automatically.
