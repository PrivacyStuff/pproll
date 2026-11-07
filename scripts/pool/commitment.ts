const FIELD_BYTES = 32;
const LIMB_BYTES = 8;
const LIMB_COUNT = 4;

/** Big-endian field element. The circuit and the on-chain hash both use this order. */
export function be32(value: bigint): Buffer {
  const out = Buffer.alloc(FIELD_BYTES);
  let rest = value;
  for (let index = FIELD_BYTES - 1; index >= 0; index -= 1) {
    out[index] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  if (rest !== 0n) throw new Error("value does not fit in a field");
  return out;
}

/**
 * Four u64 limbs, least significant first.
 * The circuit packs them as `((blind3 << 64 | blind2) << 64 | blind1) << 64 | blind0`.
 */
export function limbs(blinding: Uint8Array): [bigint, bigint, bigint, bigint] {
  if (blinding.byteLength !== FIELD_BYTES) throw new Error("a blinding is 32 bytes");
  const out: bigint[] = [];
  for (let limb = 0; limb < LIMB_COUNT; limb += 1) {
    let value = 0n;
    const start = FIELD_BYTES - LIMB_BYTES - limb * LIMB_BYTES;
    for (let byte = 0; byte < LIMB_BYTES; byte += 1) {
      const next = blinding[start + byte];
      if (next === undefined) throw new Error("blinding limb is short");
      value = (value << 8n) | BigInt(next);
    }
    out.push(value);
  }
  const [blind0, blind1, blind2, blind3] = out;
  if (blind0 === undefined || blind1 === undefined || blind2 === undefined || blind3 === undefined) {
    throw new Error("a blinding has four limbs");
  }
  return [blind0, blind1, blind2, blind3];
}
