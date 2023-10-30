<script lang="ts">
	import _sodium from 'libsodium-wrappers-sumo';

	import { page } from '$app/stores';

	import { PUBLIC_API_URL, PUBLIC_B2_BRIDGE_URL } from '$env/static/public';

	import axios from 'axios';
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import FooterText from '$lib/FooterText.svelte';

	let progress = 0;

	let isDownloading = false;

	let decryptedName = '';
	let decryptedMime = '';
	let fileSize = 0;

	let fileKey: Uint8Array | null = null;
	let keySalt: Uint8Array | null = null;
	let hashedFileKey = '';

	let isChunkedUpload = false;

	interface metadataData {
		encrypted_name: string;
		encrypted_name_header: string;
		data_header: string;
		max_downloads: number;
		expires_at: number;
		encrypted_mime: string;
		encrypted_mime_header: string;
		size: number;
		chunk_uploaded: boolean;
	}

	let metadata: metadataData = {} as any;

	onMount(() => {
		if (browser) {
			init();
		}
	});

	const init = async () => {
		await getCryptoData();
		await getMetadata();
	};

	const getMetadata = async () => {
		const hashedKey = hashedFileKey;
		const key = fileKey;
		const salt = keySalt;
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

		let keyB64 = fragment;

		// backwards compatibility
		if (fragment.includes(',')) {
			// split and get [0]
			const fragmentSplit = fragment.split(',');
			keyB64 = fragmentSplit[0];
		}

		// check if ?chunked is present
		if (window.location.search.includes('chunked')) {
			isChunkedUpload = true;
		}

		// decode
		const key = _sodium.from_base64(keyB64, _sodium.base64_variants.URLSAFE_NO_PADDING);

		// get salt from server
		const saltRes = await fetch(`${PUBLIC_API_URL}/argon_salt/${$page.params.id}`);

		const saltData: {
			success: boolean;
			message: string;
			data: string;
		} = await saltRes.json();

		if (!saltData.success) {
			alert(saltData.message);
			throw 'Unable to retrieve salt';
		}

		const salt = _sodium.from_base64(saltData.data, _sodium.base64_variants.URLSAFE_NO_PADDING);

		const hashedKey = _sodium.crypto_pwhash(
			32,
			keyB64,
			salt,
			3, // operations limit
			1024 * 1024 * 64, // memory limit (8MB)
			_sodium.crypto_pwhash_ALG_ARGON2ID13,
			'base64'
		);

		fileKey = key;
		keySalt = salt;
		hashedFileKey = hashedKey;
	};

	interface Chunk {
		uuid: string;
		transaction_uuid: string;
		data_header: string;
		chunk_number: number;
		uploaded_at: number;
	}
	async function uInt8ArrayConcat(arrays: Uint8Array[]) {
		// sum of individual array lengths
		let totalLength = arrays.reduce((acc, value) => acc + value.length, 0);
		if (!arrays.length) return null;
		let result = new Uint8Array(totalLength);
		// for each array - copy it over result
		// next array is copied right after the previous one
		let length = 0;
		for (let array of arrays) {
			result.set(array, length);
			length += array.length;
		}
		return result;
	}

	const chunkDownload = async () => {
		const hashedKey = hashedFileKey;
		const key = fileKey;
		const salt = keySalt;

		if (!key || !salt || !hashedKey) return;

		isDownloading = true;

		// get chunks
		const chunkRes = await fetch(
			`${PUBLIC_API_URL}/chunks/${$page.params.id}?hashed_key=${hashedFileKey}`
		);

		const chunkData: {
			success: boolean;
			message: string;
			data: Chunk[];
		} = await chunkRes.json();

		if (!chunkData.success) {
			alert(chunkData.message);
			throw 'Unable to retrieve chunks';
		}

		const chunksInfo = chunkData.data;

		const totalChunks = chunksInfo.length;

		let decryptedChunks: Uint8Array[] = [];

		// go through all the chunks and download them
		for (let i = 0; i < totalChunks; i++) {
			const chunk = chunksInfo[i];

			const chunkHeader = _sodium.from_base64(
				chunk.data_header,
				_sodium.base64_variants.URLSAFE_NO_PADDING
			);

			const chunkState = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(chunkHeader, key);

			const chunkRes = await fetch(
				`${PUBLIC_API_URL}/chunk/${$page.params.id}/${chunk.uuid}?hashed_key=${hashedFileKey}`
			);

			const chunkData: {
				success: boolean;
				message: string;
				data: string;
			} = await chunkRes.json();

			if (!chunkData.success) {
				alert(chunkData.message);
				throw 'Unable to retrieve chunk auth';
			}

			// download it from the bridge
			const chunkDownloadRes = await fetch(
				`${PUBLIC_B2_BRIDGE_URL}?uuid=${$page.params.id}&auth=${chunkData.data}&chunk=true&chunk_id=${chunk.uuid}&transaction_id=${chunk.transaction_uuid}`
			);

			const chunkDownloadData = await chunkDownloadRes.arrayBuffer();

			const chunkBytes = new Uint8Array(chunkDownloadData);

			const decryptedChunkBytes = _sodium.crypto_secretstream_xchacha20poly1305_pull(
				chunkState,
				chunkBytes,
				null
			);

			// append to the file
			decryptedChunks.push(decryptedChunkBytes.message);

			progress = (i + 1) / totalChunks;
		}

		// download the file

		// assemble the decrypted chunks
		const connectedChunks = await uInt8ArrayConcat(decryptedChunks);

		if (!connectedChunks) {
			alert('Unable to assemble chunks');
			throw 'Unable to assemble chunks';
		}

		const blob = new Blob([connectedChunks.buffer], { type: decryptedMime });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');

		a.href = url;

		a.download = decryptedName;

		document.body.appendChild(a);

		a.click();
	};

	const downloadFile = async () => {
		const hashedKey = hashedFileKey;
		const key = fileKey;
		const salt = keySalt;

		if (!key || !salt || !hashedKey) return;

		isDownloading = true;

		if (metadata.chunk_uploaded) {
			await chunkDownload();
			return;
		}

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
	<div class="disclaimers">
		{#if browser}
			<a
				href={`mailto:contact@horizon.pics?subject=Send Abuse Report&body=The following link contains abusive material: ${window.location.href}.`}
				><p class="abuse">Report Abuse</p></a
			>
		{/if}
		<FooterText />
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
		flex-direction: column;

		.disclaimers {
			text-align: center;
			font-size: 0.75rem;
			color: white;
			width: 25rem;
			margin-top: 0.5rem;

			@media only screen and (max-width: 800px) {
				width: 90%;
			}

			.abuse {
				color: rgb(255, 123, 123);
			}
		}

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
