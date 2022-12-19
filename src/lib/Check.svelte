<script lang="ts">
	export let selected = false;
	export let changeSelected: () => void;
	export let label = '';
	export let style = '';
</script>

<div class="parent" {style}>
	<!-- svelte-ignore a11y-click-events-have-key-events -->
	<div class={`container${selected ? ' sel' : ''}`} on:click={changeSelected} />
	{#if label}
		<p>{label}</p>
	{/if}
</div>

<style lang="scss">
	.container {
		min-height: 20px;
		min-width: 20px;
		height: 20px;
		width: 20px;

		border-radius: 5px;

		box-shadow: 0px 24px 48px 0 rgba(0, 0, 0, 0.16);

		display: flex;
		justify-content: center;
		align-items: center;
		border: 2px solid #2e2eb3;

		cursor: pointer;
	}

	.sel {
		background-color: #2e2eb3;
	}

	.parent {
		display: flex;
		gap: 0.5rem;
		color: white;
		align-items: center;
	}
</style>
