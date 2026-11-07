export interface KitSigner {
  readonly address: string;
}

export function createKeyPairSignerFromPrivateKeyBytes(bytes: Uint8Array): Promise<KitSigner>;

export function signTransactionWithSigners(signers: readonly KitSigner[], transaction: unknown): Promise<unknown>;

export function sendTransactionWithoutConfirmingFactory(config: {
  rpc: unknown;
}): (transaction: unknown, options: { commitment: "confirmed" }) => Promise<void>;

export function getSignatureFromTransaction(transaction: unknown): string;
