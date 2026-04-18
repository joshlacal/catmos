// Auto-generated at build time from ../../docs/brand/tokens/Catbird.pkl
// via scripts/generate-brand.sh. The JSON import is type-checked by the
// companion `types.ts` (hand-authored to mirror the Pkl schema).
import raw from './tokens.json';
import type { Tokens, Palette } from './types';

export const brand: Tokens = raw as unknown as Tokens;

export type { Tokens, Palette };

/**
 * The mode-adaptive accent value. Use this in runtime theming code;
 * the gradient itself (see `brandGradient`) does not adapt.
 */
export function accentFor(mode: 'light' | 'dark', palette: keyof typeof brand.color.all = 'catbird'): string {
  const p = brand.color.all[palette] as Palette;
  return mode === 'light' ? p.accentLight : p.accentDark;
}

/**
 * The canonical Catbird brand gradient. Identical in light and dark modes.
 * Used for app icon backgrounds, hero blocks, sent-message bubbles,
 * primary gradient buttons, and marketing surfaces.
 */
export const brandGradient = `linear-gradient(135deg, ${brand.color.catbird.accentLight} 0%, ${brand.color.catbird.accentDark} 100%)`;
