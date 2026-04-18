<script lang="ts">
  interface Props {
    children?: import('svelte').Snippet;
  }
  let { children }: Props = $props();
</script>

<h1 class="display-title">
  {#if children}{@render children()}{/if}
</h1>

<style>
  .display-title {
    font-family: 'Inter var', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: clamp(34px, 4vw, 40px);
    font-weight: 800;
    line-height: 1.05;
    letter-spacing: -0.02em;
    color: var(--text-primary);
    margin: 0;
  }
  /* Extended-width signature — applies only when the user's browser
     supports the wdth variable-font axis (Inter var or a system font
     that honors font-stretch). */
  @supports (font-variation-settings: normal) {
    .display-title {
      font-variation-settings: 'wdth' 125, 'wght' 800, 'opsz' 36;
    }
  }
  @supports not (font-variation-settings: normal) {
    .display-title {
      font-stretch: 125%;
    }
  }
</style>
