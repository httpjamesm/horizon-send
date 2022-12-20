<script lang="ts">
	import _sodium from 'libsodium-wrappers';

	import { page } from '$app/stores';

	import { PUBLIC_API_URL, PUBLIC_B2_BRIDGE_URL } from '$env/static/public';

	import axios from 'axios';
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';

	let progress = 0;

	let isDownloading = false;

	let decryptedName = '';
	let decryptedMime = '';
	let fileSize = 0;

	interface metadataData {
		encrypted_name: string;
		encrypted_name_header: string;
		data_header: string;
		max_downloads: number;
		expires_at: number;
		encrypted_mime: string;
		encrypted_mime_header: string;
		size: number;
	}

	let metadata: metadataData = {} as any;

	onMount(() => {
		if (browser) {
			getMetadata();
		}
	});

	const getMetadata = async () => {
		const { key, salt, hashedKey } = await getCryptoData();

		if (!key || !salt || !hashedKey) return;

		const metadataRes = await fetch(
			`${PUBLIC_API_URL}/meta/${$page.params.id}?hashed_key=${hashedKey}`
		);

		const metadataResponse: {
			success: boolean;
			message: string;
			data: metadataData;
		} = await metadataRes.json();

		if (!metadataResponse.success) {
			alert(metadataResponse.message);
			throw 'Unable to get metadata';
		}

		metadata = metadataResponse.data;

		// get the name header
		const nameHeader = _sodium.from_base64(
			metadata.encrypted_name_header,
			_sodium.base64_variants.URLSAFE_NO_PADDING
		);

		// create a new state for the name
		const nameState = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(nameHeader, key);

		// decrypt the file name
		const decryptedFileNameBytes = _sodium.crypto_secretstream_xchacha20poly1305_pull(
			nameState,
			_sodium.from_base64(metadata.encrypted_name),
			null
		);

		// decode name
		const dec = new TextDecoder();
		decryptedName = dec.decode(decryptedFileNameBytes.message);

		fileSize = metadata.size;

		// decrypt mime
		const mimeHeader = _sodium.from_base64(
			metadata.encrypted_mime_header,
			_sodium.base64_variants.URLSAFE_NO_PADDING
		);

		const mimeState = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(mimeHeader, key);

		const encryptedMimeBytes = _sodium.from_base64(
			metadata.encrypted_mime,
			_sodium.base64_variants.URLSAFE_NO_PADDING
		);

		const decryptedMimeBytes = _sodium.crypto_secretstream_xchacha20poly1305_pull(
			mimeState,
			encryptedMimeBytes,
			null
		);

		decryptedMime = dec.decode(decryptedMimeBytes.message);
	};

	const getCryptoData = async () => {
		await _sodium.ready;

		// get key from the #
		const fragment = window.location.hash.substring(1);

		const fragmentSplit = fragment.split(',');

		if (fragmentSplit.length < 2) {
			alert('Invalid URL');
			throw 'Invalid key data in URL';
		}

		const keyB64 = fragmentSplit[0];

		const saltB64 = fragmentSplit[1];

		// decode
		const key = _sodium.from_base64(keyB64, _sodium.base64_variants.URLSAFE_NO_PADDING);

		const salt = _sodium.from_base64(saltB64, _sodium.base64_variants.URLSAFE_NO_PADDING);

		const hashedKey = _sodium.crypto_pwhash(
			32,
			keyB64,
			salt,
			3, // operations limit
			1024 * 1024 * 64, // memory limit (8MB)
			_sodium.crypto_pwhash_ALG_ARGON2ID13,
			'base64'
		);

		return {
			key,
			salt,
			hashedKey
		};
	};

	const downloadFile = async () => {
		const { key, salt, hashedKey } = await getCryptoData();

		if (!key || !salt) return;

		isDownloading = true;

		const dlRequest = await fetch(
			`${PUBLIC_API_URL}/download/${$page.params.id}?hashed_key=${hashedKey}`
		);

		if (dlRequest.status !== 200) {
			alert('Unable to get encrypted file auth');
			return;
		}

		const downloadRequestRes: {
			success: boolean;
			message: string;
			data: string;
		} = await dlRequest.json();

		if (!downloadRequestRes.success) {
			alert(downloadRequestRes.message);
			return;
		}

		// download from the bridge
		const res = await axios.get(
			`${PUBLIC_B2_BRIDGE_URL}?uuid=${$page.params.id}&auth=${downloadRequestRes.data}`,
			{
				onDownloadProgress: (progressEvent) => {
					// @ts-ignore
					progress = progressEvent.loaded / progressEvent.total;
				},
				responseType: 'arraybuffer'
			}
		);

		const file = res.data as ArrayBuffer;

		// get the header
		const dataHeader = _sodium.from_base64(
			metadata.data_header,
			_sodium.base64_variants.URLSAFE_NO_PADDING
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
			type: decryptedMime || 'application/octet-stream'
		});

		const url = URL.createObjectURL(newFile);

		let a = document.createElement('a');

		a.href = url;

		a.download = decryptedName;

		a.click();
	};
</script>

<svelte:head>
	<title>Horizon Send - Secure File Sharing</title>
	<meta
		name="description"
		content="Someone shared an encrypted file with you. Visit the link to decrypt and download it."
	/>
</svelte:head>

<div class="parent">
	<div class="container">
		<h1>Horizon Send</h1>
		<h2>End-to-end encrypted file sharing.</h2>
		<p>Someone shared an encrypted file with you. Click the button below to download it.</p>
		<p class="preview-details">
			{decryptedName} • {decryptedMime} • {Math.ceil(fileSize / 1024 / 1024)} MB
		</p>
		{#if isDownloading}
			<div style="display: flex; gap: 1rem; align-items: center;">
				<progress class="progress-bar" value={progress} max="1" />
				<p style="width: 2rem;">
					{Math.ceil(progress * 100)}%
				</p>
			</div>
		{:else}
			<button class="download" on:click={downloadFile} disabled={!decryptedName}
				>{#if !decryptedName}Decrypting...{:else}Download{/if}</button
			>
		{/if}
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

			.preview-details {
				margin-top: 1rem;
			}

			.progress-bar {
				width: 100%;

				-webkit-appearance: none;
				appearance: none;
				border-radius: 50px;
				border: 0;
			}

			.progress-bar::-webkit-progress-bar {
				border-radius: 50px;
			}

			.progress-bar::-webkit-progress-value {
				background: #3e3eb3;
				border-radius: 50px;
				border: 0;
			}

			.download {
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

				&:disabled {
					background-color: #7272ac;
					cursor: not-allowed;
				}
			}
		}
	}
</style>
