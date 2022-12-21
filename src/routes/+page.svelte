<script lang="ts">
	import _sodium from 'libsodium-wrappers';

	import axios from 'axios';

	import { PUBLIC_API_URL, PUBLIC_TURNSTILE_KEY, PUBLIC_UPLOAD_LIMIT } from '$env/static/public';

	import { Turnstile } from 'svelte-turnstile';

	import FaCog from 'svelte-icons/fa/FaCog.svelte';
	import Check from '$lib/Check.svelte';

	import { copy } from 'svelte-copy';
	import FaCopy from 'svelte-icons/fa/FaCopy.svelte';
	import FaQrcode from 'svelte-icons/fa/FaQrcode.svelte';

	import { SvelteToast, toast } from '@zerodevx/svelte-toast';
	import FooterText from '$lib/FooterText.svelte';

	import JSZip from 'jszip';

	import QR from 'qrcode';

	let fileInput: HTMLInputElement;

	let uploadUuid = '';
	let uploadKey = '';

	let stage: 'verifying' | 'upload' | 'uploading' | 'finished' = 'verifying';

	let progress = 0;

	let showMaxDownloads = false;

	let maxDownloads = 0;
	let expiresAfter: 3600 | 21600 | 86400 | 259200 | 604800 = 604800;

	let showOptions = false;

	let turnstileToken = '';

	let showQrCode = false;
	let qrCodeData = '';

	let isDragging = false;

	// get the file
	const encryptAndUpload = async (files: FileList) => {
		// const files = (<HTMLInputElement>e.target).files;
		if (!files) return;
		// get the file contents
		const file = files[0];

		let fileContents: ArrayBuffer;

		if (files.length === 1) {
			if (file.size > Number(PUBLIC_UPLOAD_LIMIT) * 1024 * 1024) {
				alert(`File size is too large. Max size is ${PUBLIC_UPLOAD_LIMIT}MB`);
				return;
			}

			// create reader
			const reader = new FileReader();

			// read the file
			reader.readAsArrayBuffer(file);

			// wait for the file to be read
			await new Promise((resolve) => {
				reader.onload = resolve;
			});
			fileContents = reader.result as ArrayBuffer;
		} else {
			// zip the files
			let zip = new JSZip();

			for (let i = 0; i < files.length; i++) {
				const file = files[i];
				if (file.size > Number(PUBLIC_UPLOAD_LIMIT) * 1024 * 1024) {
					alert(`File size is too large. Max size is ${PUBLIC_UPLOAD_LIMIT}MB`);
					return;
				}
				const reader = new FileReader();
				reader.readAsArrayBuffer(file);
				await new Promise((resolve) => {
					reader.onload = resolve;
				});
				zip.file(file.name, reader.result as ArrayBuffer);
			}

			fileContents = await zip.generateAsync({ type: 'arraybuffer' });
		}

		const uIntFileContents = new Uint8Array(fileContents);

		// get the sodium library
		await _sodium.ready;
		const sodium = _sodium;

		// generate a random key
		const key = sodium.randombytes_buf(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES);

		// convert key to b64
		const keyB64 = sodium.to_base64(key, sodium.base64_variants.URLSAFE_NO_PADDING);

		// create random salt
		const saltBytes = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);

		// convert saltBytes to b64
		const saltB64 = sodium.to_base64(saltBytes, sodium.base64_variants.URLSAFE_NO_PADDING);

		// hash key with argon2id
		const hashedKeyString = _sodium.crypto_pwhash(
			32,
			keyB64,
			saltBytes,
			3, // operations limit
			1024 * 1024 * 64, // memory limit (8MB)
			_sodium.crypto_pwhash_ALG_ARGON2ID13,
			'base64'
		);

		// create a new state
		const dataState = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);

		// encrypt the file
		const encryptedFile = sodium.crypto_secretstream_xchacha20poly1305_push(
			dataState.state,
			uIntFileContents,
			null,
			sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
		);

		// get the header
		const dataHeader = dataState.header;

		// convert header to base64
		const headerBase64 = sodium.to_base64(dataHeader, sodium.base64_variants.URLSAFE_NO_PADDING);

		// get the file name
		let fileName = file.name;

		if (files.length > 1) {
			fileName = `send-archive-${new Date().getTime()}.zip`;
		}

		// create a new state for the name
		const nameState = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);

		const enc = new TextEncoder();

		// encrypt the file name
		const encryptedFileName = sodium.crypto_secretstream_xchacha20poly1305_push(
			nameState.state,
			enc.encode(fileName),
			null,
			sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
		);

		const encryptedFileNameBase64 = sodium.to_base64(
			encryptedFileName,
			sodium.base64_variants.URLSAFE_NO_PADDING
		);

		// get the header
		const nameHeader = nameState.header;

		// convert header to base64
		const nameHeaderBase64 = sodium.to_base64(
			nameHeader,
			sodium.base64_variants.URLSAFE_NO_PADDING
		);

		// encrypt mime
		const mimeState = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);

		let mimeType = file.type;

		if (files.length > 1) {
			mimeType = 'application/zip';
		}

		const encryptedMime = sodium.crypto_secretstream_xchacha20poly1305_push(
			mimeState.state,
			enc.encode(mimeType),
			null,
			sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
		);

		const encryptedMimeBase64 = sodium.to_base64(
			encryptedMime,
			sodium.base64_variants.URLSAFE_NO_PADDING
		);

		const mimeHeaderB64 = sodium.to_base64(
			mimeState.header,
			sodium.base64_variants.URLSAFE_NO_PADDING
		);

		// create a new form data object
		let formData = new FormData();
		formData.append('data', new Blob([encryptedFile], { type: 'application/octet-stream' }));
		formData.append('data_header', headerBase64);
		formData.append('name', encryptedFileNameBase64);
		formData.append('name_header', nameHeaderBase64);
		formData.append('hashed_key', hashedKeyString);
		formData.append('hashed_key_salt', saltB64);
		formData.append('max_downloads', showMaxDownloads ? maxDownloads.toString() : '0');
		formData.append('mime', encryptedMimeBase64);
		formData.append('mime_header', mimeHeaderB64);
		formData.append('turnstile', turnstileToken);
		formData.append('expires_after', expiresAfter.toString());

		stage = 'uploading';

		const res = await axios.post(`${PUBLIC_API_URL}/upload`, formData, {
			// @ts-ignore
			onUploadProgress: (e: { loaded: number; total: number }) => {
				progress = e.loaded / e.total;
			}
		});

		const data: {
			success: true;
			message: string;
			data: string;
		} = res.data;

		if (!data.success) {
			alert(data.message);
			throw `unable to upload file: ${data.message}`;
		}

		uploadUuid = data.data;
		uploadKey = `${keyB64}`;
		stage = 'finished';

		progress = 0;

		qrCodeData = await QR.toDataURL(`${window.location.href}download/${uploadUuid}#${uploadKey}`);
	};

	const turnstileCallback = (token: { detail: { token: string } }) => {
		turnstileToken = token.detail.token;
		stage = 'upload';
	};

	const onDrop = async (e: DragEvent) => {
		const files = e.dataTransfer?.files;

		if (!files) {
			return;
		}

		await encryptAndUpload(files);
	};
</script>

<svelte:head>
	<title>Horizon Send - Secure File Sharing</title>
	<meta
		name="description"
		content="Horizon Send is a secure file sharing service that uses XChaCha20 end-to-end zero-knowledge encryption to protect your files."
	/>
</svelte:head>

<div
	class="parent"
	on:drop|preventDefault={onDrop}
	on:dragover|preventDefault
	on:dragenter={() => {
		isDragging = true;
	}}
	on:dragleave={() => {
		isDragging = false;
	}}
>
	<div class="container">
		<h1>Horizon Send</h1>
		<h2>End-to-end encrypted file sharing.</h2>
		<p>
			Horizon Send protects your uploads with zero-knowledge encryption. No one except those you
			share the link with can access your shared content.
		</p>
		{#if stage === 'verifying'}
			<p class="verifying">Please wait while we verify your humanity...</p>
		{:else if stage === 'upload'}
			{#if isDragging}
				<div class="dropzone">
					<p>Drop your files here</p>
				</div>
			{:else}
				<button
					class="upload"
					on:click={() => {
						if (!fileInput) return;
						fileInput.click();
					}}>Upload Securely</button
				>
			{/if}
			<p class="upload-limit">Max {PUBLIC_UPLOAD_LIMIT} MB • Drag & Drop Supported</p>
			<div class="options-toggle-parent">
				<!-- svelte-ignore a11y-click-events-have-key-events -->
				<div
					class="options-toggle"
					on:click={() => {
						showOptions = !showOptions;
					}}
				>
					<div class="icon">
						<FaCog />
					</div>
					<p>Options</p>
				</div>
			</div>
			{#if showOptions}
				<div class="options">
					<div class="option">
						<Check
							selected={showMaxDownloads}
							label="Set Download Limit"
							style="margin-top: .5rem;"
							changeSelected={() => {
								showMaxDownloads = !showMaxDownloads;
							}}
						/>
						{#if showMaxDownloads}
							<input type="number" min="1" max="20" bind:value={maxDownloads} class="input-field" />
						{/if}
					</div>
					<div class="option">
						<label for="expires-after">Expires After</label>
						<select id="expires-after" bind:value={expiresAfter} class="input-field">
							<option value={3600}>1 Hour</option>
							<option value={21600}>6 Hours</option>
							<option value={86400}>1 Day</option>
							<option value={259200}>3 Days</option>
							<option value={604800}>1 Week</option>
						</select>
					</div>
				</div>
			{/if}
		{:else if stage === 'uploading'}
			<div style="display: flex; gap: 1rem; align-items: center;">
				<progress class="progress-bar" value={progress} max="1" />
				<p style="width: 2rem;">
					{Math.ceil(progress * 100)}%
				</p>
			</div>
		{:else if stage === 'finished'}
			<div class="link-parent">
				<input
					disabled
					class="input"
					type="text"
					value={`${window.location.href}download/${uploadUuid}#${uploadKey}`}
				/>
				<button
					class="copy"
					use:copy={`${window.location.href}download/${uploadUuid}#${uploadKey}`}
					on:click={() => {
						toast.push('Copied link to clipboard', {
							theme: {
								'--toastColor': 'mintcream',
								'--toastBackground': 'rgba(72,187,120,0.9)',
								'--toastBarBackground': '#2F855A'
							}
						});
					}}
				>
					<div class="icon">
						<FaCopy />
					</div>
				</button>
				<button
					class="copy"
					on:click={() => {
						showQrCode = !showQrCode;
					}}
				>
					<div class="icon">
						<FaQrcode />
					</div>
				</button>
			</div>
			{#if showQrCode}
				<div style="margin-top: 1rem;" />
				<img src={qrCodeData} alt="Link QR Code" />
			{/if}
			<button
				class="upload"
				on:click={() => {
					window.location.reload();
				}}>Upload Another</button
			>
		{/if}

		<Turnstile siteKey={PUBLIC_TURNSTILE_KEY} on:turnstile-callback={turnstileCallback} />

		<input
			style="display: none"
			type="file"
			id="file"
			accept="*/*"
			multiple
			bind:this={fileInput}
			on:change={async (e) => {
				// @ts-ignore
				const files = e.target.files;
				encryptAndUpload(files);
			}}
		/>
	</div>
	<div class="disclaimers">
		<p>
			Your IP address is stored irreversibly hashed to prevent abuse. It is permanently deleted
			after its associated file expires.
		</p>
		<FooterText />
	</div>
</div>

<SvelteToast />

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
		}

		.container {
			display: flex;
			justify-content: center;
			flex-direction: column;
			background-color: #1b1b58;
			border: 1px solid rgb(54, 50, 121);
			border-radius: 20px;
			box-sizing: border-box;
			margin: 0.5rem;
			transition-duration: 0.25s;
			box-shadow: rgba(0, 0, 0, 0.2) 0px 0px 10px;
			height: fit-content;
			width: 22rem;
			margin: 0 12px;
			padding: 32px;
			color: white;

			.dropzone {
				@extend .upload;

				background-color: transparent !important;
				font-weight: bold;
				color: white;
				border: 3px dashed #2e2eb3 !important;

				display: flex;
				justify-content: center;
				align-items: center;
				text-align: center;
			}

			.link-parent {
				display: flex;
				gap: 0.5rem;

				.copy {
					@extend .upload;
					width: 3rem;
					display: flex;
					justify-content: center;
					align-items: center;

					.icon {
						width: 1rem;
						display: flex;
						justify-content: center;
						align-items: center;
					}
				}
			}

			.upload-limit {
				text-align: center;
				font-size: 0.75rem;
			}

			.options-toggle-parent {
				width: 100%;
				display: flex;
				justify-content: flex-end;

				.options-toggle {
					margin-top: 0.5rem;

					color: #2e2eb3;

					display: flex;
					align-items: center;
					gap: 0.25rem;

					width: fit-content;

					.icon {
						width: 1rem;
						display: flex;
						align-items: center;
						justify-content: center;
					}

					padding: 0.5rem;
					box-sizing: border-box;
					cursor: pointer;
					user-select: none;

					transition-duration: 0.5s;

					border-radius: 10px;

					&:hover {
						background-color: rgba(255, 255, 255, 0.04);
					}
				}
			}

			.options {
				.option {
					.input-field {
						margin-top: 0.5rem;
						margin-bottom: 0.5rem;
						background-color: #2e2eb3;
						padding: 0.5rem;
						box-sizing: border-box;
						height: 2rem;
						min-width: 5rem;
						color: white;
						border-radius: 5px;
						border: none;
					}
				}
			}

			.progress-bar {
				width: 100%;

				-webkit-appearance: none;
				appearance: none;
				background: transparent;
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

			.input {
				width: 100%;
				height: 3rem;
				margin-top: 1rem;
				background-color: rgb(10, 10, 72);
				color: white;
				transition-duration: 0.25s;
				padding: 0.5rem;
				box-sizing: border-box;
				border: 2px solid transparent;
				font-size: 1rem;

				border-radius: 10px;
			}
		}
	}

	.verifying {
		color: rgb(84, 255, 158);
	}
</style>
