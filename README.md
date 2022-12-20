# horizon-send

Horizon Send is a secure file sharing service that uses zero-knowledge end-to-end encryption to protect your files.

## Encryption

Horizon Send uses `libsodium-wrappers` to encrypt files and associated metadata with AEAD XChaCha20-Poly1305 secret stream.

### Flow

1. Bob selects a file in the menu.
2. Client grabs all the data about the file, such as contents, file name and mime-type.
3. Client generates a random XChaCha20 secret stream key.
4. Client hashes key with Argon2id13 with a cryptographically random salt.
5. Client encrypts file data and metadata with the key.
6. Client uploads the encrypted file and metadata to the server with the Argon2id13 hashed key for server-side validation.
7. Client converts the key and salt to base64 and appends it to the download endpoint via URL fragment (which the browser does not send to the server).
8. Bob copies the URL and sends it to Alice.
9. Alice visits the URL and clicks "Download".
10. Client grabs the key and salt from the URL fragment.
11. Client hashes the key with Argon2id13 with the salt.
12. Client requests the encrypted file and metadata from the server by passing along the hashed key.
13. Client decrypts the file and metadata with the key.
14. Client saves the file to disk.

## Development


Once you've created a project and installed dependencies with `npm install` (or `pnpm install` or `yarn`), start a development server:

```bash
npm run dev

# or start the server and open the app in a new browser tab
npm run dev -- --open
```

### Building

To create a production version of your app:

```bash
npm run build
```

You can preview the production build with `npm run preview`.

> To deploy your app, you may need to install an [adapter](https://kit.svelte.dev/docs/adapters) for your target environment.
