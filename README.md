# SSH Touch ID Askpass

An `SSH_ASKPASS` program for macOS. It unlocks the PIN for FIDO2 security keys (such as a YubiKey) with Touch ID, shows native dialogs for SSH passwords and host-key confirmations, and tells you which application asked.

## Features

- **Touch ID for security key PINs**: the PIN is saved in the macOS keychain the first time you enter it. After that, Touch ID (or your login password) unlocks it.
- **Shows who is asking**: dialogs name the application and command that triggered the request, e.g. "Terminal is trying to use your SSH key PIN for git push origin main." This also works when the key is held by `ssh-agent`, by following the agent's socket back to the connected client.
- **Password prompts**: regular SSH password prompts get a secure input dialog.
- **Host key confirmation**: "Are you sure you want to continue connecting?" gets a Connect/Cancel dialog. Cancel is the default, so pressing Return never accepts an unknown host key.
- **Logging**: operations are logged to `~/.ssh/ask-pass-touchid.log` for troubleshooting.

## Requirements

- macOS 15.5 or later, with Touch ID (the login password works as a fallback)
- Xcode, to build from source
- For PIN support: an SSH key backed by a FIDO2 security key that requires a PIN (`ed25519-sk` with `verify-required`)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Spyctor/SSH-Handler.git
   cd SSH-Handler
   ```

2. Build it. No Apple developer account is needed; the binary is signed to run locally:

   ```bash
   ./build.sh
   ```

   With an ad-hoc signature, macOS asks once for keychain access after each rebuild (choose "Always Allow"). If you have an Apple developer team, sign with it to avoid that:

   ```bash
   DEVELOPMENT_TEAM=<your team id> ./build.sh
   ```

3. Install the executable:

   ```bash
   cp build/Build/Products/Release/ask-pass-touchid ~/.ssh/
   chmod 755 ~/.ssh/ask-pass-touchid
   ```

4. Point SSH at it in your shell configuration (e.g. `~/.zshrc`):

   ```bash
   export SSH_ASKPASS="$HOME/.ssh/ask-pass-touchid"
   ```

   SSH only uses the askpass when it has no terminal, or when `SSH_ASKPASS_REQUIRE=prefer` or `force` is set. `ssh-agent` uses the `SSH_ASKPASS` it was started with, so restart the agent after changing it.

## How it works

SSH runs the askpass with the prompt text as its only argument and reads the answer from stdout:

| Prompt | Behaviour |
| --- | --- |
| `Enter PIN … ED25519-SK key SHA256:…` | If a PIN is stored for that key, unlock it with Touch ID. Otherwise ask for it and store it. |
| `Confirm user presence …` | A notification only; nothing is shown. Touch the security key. |
| `… (yes/no …)?` | Connect/Cancel dialog; prints `yes` or `no`. |
| `… password …` | Secure password dialog. Passwords are never stored. |

macOS titles the Touch ID sheet "<calling program> is trying to …". To show the requesting application there, the Touch ID check runs from a copy of the binary named after that application, cached in `~/Library/Caches/ask-pass-touchid/`.

## Security notes

- PINs are stored as generic passwords (service `SSH_SK_PIN`, account = key fingerprint) with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so they aren't synced or migrated to other devices.
- Touch ID is checked by this program before it reads the PIN. It isn't a keychain access-control flag on the item itself.
- The log records prompts and outcomes, never PINs or passwords.
- The security key still requires a physical touch for every signature.

## License

[PolyForm Strict 1.0.0](LICENSE.md). You're free to build and use this for personal or other noncommercial purposes. You may not sell it, use it commercially, distribute it, or publish modified versions. Contact the author for any other use.
