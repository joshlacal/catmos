// Hand-authored TypeScript types mirroring the Pkl schema at
// ../../../../docs/brand/tokens/Catbird.pkl. Kept in sync by convention;
// the drift-check CI workflow catches value drift, not shape drift.

export interface Palette {
  accentLight: string;
  accentDark: string;
  /** Text-safe accent for light mode — clears WCAG AA-normal on white. */
  accentText: string;
  /** Text-safe accent for dark mode. */
  accentTextDark: string;
  gradientPartner: string;
}

export interface Semantic {
  success: string;
  warning: string;
  danger: string;
  encryptionShield: string;
}

export interface DarkScheme {
  background: string;
  surface: string;
  surfaceContainer: string;
  surfaceContainerHigh: string;
  onSurface: string;
  onSurfaceVariant: string;
}

export interface ColorTokens {
  catbird: Palette;
  twilight: Palette;
  lavender: Palette;
  sunrise: Palette;
  aurora: Palette;
  dusk: Palette;
  midnight: Palette;
  all: Record<'catbird' | 'twilight' | 'lavender' | 'sunrise' | 'aurora' | 'dusk' | 'midnight', Palette>;
  semantic: Semantic;
  dim: DarkScheme;
  trueBlack: DarkScheme;
}

export interface SpaceTokens {
  fine: number;
  s1: number; s2: number; s3: number; s4: number; s5: number;
  s6: number; s8: number; s10: number; s12: number; s16: number;
}

export interface RadiusTokens {
  xs: number; sm: number; md: number; lg: number; xl: number; full: number;
}

export interface FontFamily {
  apple: string;
  android: string;
  webStack: string;
}

export interface TypeRole {
  minSize: number;
  maxSize: number;
  weight: number;
  widthPercent: number;
  trackingEm: number;
  useDisplayFont: boolean;
}

export interface TypeTokens {
  primary: FontFamily;
  display: TypeRole;
  headline: TypeRole;
  title: TypeRole;
  body: TypeRole;
  caption: TypeRole;
  wordmark: TypeRole;
}

export interface MotionBinding {
  iosSwiftUI: string;
  androidCompose: string;
  cssTiming: string;
  cssDurationMs: number;
}

export interface MotionTokens {
  instant: MotionBinding;
  enter: MotionBinding;
  exit: MotionBinding;
  emphasis: MotionBinding;
  gesture: MotionBinding;
}

export interface GlassBinding {
  iosSwiftUIMaterial: string;
  androidElevationDp: number;
  androidSurfaceRole: string;
  webBackdropFilter: string;
}

export interface MaterialTokens {
  subtle: GlassBinding;
  regular: GlassBinding;
  strong: GlassBinding;
}

export interface Tokens {
  version: string;
  generatedAt: string;
  color: ColorTokens;
  space: SpaceTokens;
  radius: RadiusTokens;
  type: TypeTokens;
  motion: MotionTokens;
  material: MaterialTokens;
}
