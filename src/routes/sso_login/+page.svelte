<script lang="ts">
	import { PUBLIC_API_URL, PUBLIC_TURNSTILE_KEY } from '$env/static/public';
	import { Turnstile } from 'svelte-turnstile';

	const turnstileCallback = async (token: { detail: { token: string } }) => {
		// get token and requested_user from query params
		const url = new URL(window.location.href);
		const ssoToken = url.searchParams.get('token');
		const requestedUser = url.searchParams.get('requested_user');

		if (!ssoToken || !requestedUser) {
			alert('Unable to login due to incorrect URL params.');
			throw new Error('Unable to login due to incorrect URL params.');
		}

		const res = await fetch(
			`${PUBLIC_API_URL}/auth/login?token=${ssoToken}&requested_user=${requestedUser}&captcha_token=${token.detail.token}`,
			{
				credentials: 'include'
			}
		);

		const data: {
			success: boolean;
			message: string;
		} = await res.json();

		if (!res.ok || !data.success) {
			alert('Unable to sign in. Try again later.');
			throw data.message;
		}

		window.location.href = '/';
	};
</script>

<div class="parent">
	<div class="container">
		<h1>Horizon Send</h1>
		<h2>We're signing you in.</h2>
		<p>Hang tight! This should only take a few seconds...</p>
	</div>
	<Turnstile
		siteKey={PUBLIC_TURNSTILE_KEY}
		on:turnstile-callback={turnstileCallback}
		retry="never"
	/>
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
		}
	}
</style>
