// WalletConnect pairing is what mobile wallets use to reach the app. Robinhood
// Wallet, Rainbow and Trust all connect this way; browser-extension wallets are
// injected and need none of it. An unset or malformed id therefore degrades to
// extension-only connectivity instead of breaking sign-in.
const projectIdPattern = /^[0-9a-f]{32}$/i;

export function resolveWalletConnectProjectId(
  value: string | undefined = process.env.NEXT_PUBLIC_PRISM_WALLETCONNECT_PROJECT_ID,
): string | undefined {
  const trimmed = value?.trim();
  return trimmed && projectIdPattern.test(trimmed) ? trimmed : undefined;
}
