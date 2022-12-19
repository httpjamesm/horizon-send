<script lang="ts">
	import _sodium from 'libsodium-wrappers';

	import { page } from '$app/stores';

	import { PUBLIC_API_URL } from '$env/static/public';

	const downloadFile = async () => {
		// get key from the #
		const fragment = window.location.hash.substring(1);

		const fragmentSplit = fragment.split(',');

		if (fragmentSplit.length < 2) {
			alert('Invalid URL');
			return;
		}

		const keyB64 = fragmentSplit[0];

		const saltB64 = fragmentSplit[1];

		// decode
		const key = _sodium.from_base64(keyB64, _sodium.base64_variants.URLSAFE_NO_PADDING);

		const salt = _sodium.from_base64(saltB64, _sodium.base64_variants.URLSAFE_NO_PADDING);

		// hash key
		const hashedKey = _sodium.crypto_pwhash(
			32,
			keyB64,
			salt,
			3, // operations limit
			1024 * 1024 * 64, // memory limit (8MB)
			_sodium.crypto_pwhash_ALG_ARGON2ID13,
			'base64'
		);

		const metadataRes = await fetch(
			`${PUBLIC_API_URL}/meta/${$page.params.id}?hashed_key=${hashedKey}`
		);

		const metadata: {
			success: boolean;
			message: string;
			data: {
				encrypted_name: string;
				encrypted_name_header: string;
				data_header: string;
				max_downloads: number;
				expires_at: number;
				encrypted_mime: string;
				encrypted_mime_header: string;
			};
		} = await metadataRes.json();

		if (!metadata.success) {
            alert(metadata.message);
			return;
		}

		const res = await fetch(`${PUBLIC_API_URL}/download/${$page.params.id}`);

		if (!res.ok) {
			alert('Unable to download encrypted file');
			return;
		}

		const file = await res.arrayBuffer();

		// get the header
		const dataHeader = _sodium.from_base64(
			metadata.data.data_header,
			_sodium.base64_variants.URLSAFE_NO_PADDING
		);

		// get the name header
		const nameHeader = _sodium.from_base64(
			metadata.data.encrypted_name_header,
			_sodium.base64_variants.URLSAFE_NO_PADDING
		);

		// create a new state for the name
		const nameState = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(nameHeader, key);

		// decrypt the file name
		const decryptedFileName = _sodium.crypto_secretstream_xchacha20poly1305_pull(
			nameState,
			_sodium.from_base64(metadata.data.encrypted_name),
			null
		);

		// decode name
		const dec = new TextDecoder();
		const fileName = dec.decode(decryptedFileName.message);

		// decrypt mime
		const mimeHeader = _sodium.from_base64(
			metadata.data.encrypted_mime_header,
			_sodium.base64_variants.URLSAFE_NO_PADDING
		);

		const mimeState = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(mimeHeader, key);

		const decryptedMime = _sodium.crypto_secretstream_xchacha20poly1305_pull(
			mimeState,
			metadata.data.encrypted_mime,
			null
		);

		// create a new state for the data
		const dataState = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(dataHeader, key);

		const fileArrayBuffer = file;

		// decrypt the file
		const decryptedFile = _sodium.crypto_secretstream_xchacha20poly1305_pull(
			dataState,
			new Uint8Array(fileArrayBuffer),
			null
		);

		// create a new file
		const newFile = new Blob([decryptedFile.message], {
			type: dec.decode(decryptedMime.message) || 'application/octet-stream'
		});

		const url = URL.createObjectURL(newFile);

		let a = document.createElement('a');

		a.href = url;

		a.download = fileName;

		a.click();
	};
</script>

<div class="parent">
	<div class="container">
		<h1>Horizon Send</h1>
		<h2>End-to-end encrypted file sharing.</h2>
		<p>Someone shared an encrypted file with you. Click the button below to download it.</p>
		<button class="upload" on:click={downloadFile}>Download</button>
	</div>
</div>

<style lang="scss">
	.parent {
		width: 100vw;
		height: 100vh;
		background-image: url('/images/background.jpg');
		background-size: cover;
		background-repeat: no-repeat;

		display: flex;
		justify-content: center;
		align-items: center;

		.container {
			display: flex;
			justify-content: center;
			flex-direction: column;
			background-color: #1b1b58;
			border: 1px solid rgb(54, 50, 121);
			border-radius: 20px;
			padding: 2rem;
			margin: 0.5rem;
			transition-duration: 0.25s;
			box-shadow: rgba(0, 0, 0, 0.2) 0px 0px 10px;
			height: fit-content;
			max-width: 20rem;
			margin: 0 12px;
			padding: 32px;
			color: white;

			.upload {
				background-color: #2e2eb3;
				cursor: pointer;
				border: rgb(54, 50, 121);
				color: white;
				border-radius: 10px;
				padding: 0.5rem;
				box-sizing: border-box;
				height: 3rem;
				margin-top: 1rem;

				&:hover {
					background-color: #3e3eb3;
				}
			}
		}
	}
</style>
