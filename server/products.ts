// The other OpenAsy products of this install, for the product switcher (ADR 0001). Every product reads the same
// OPENASY_PRODUCTS value, `vpn=https://vpn.example.com,infrastructure=https://infra.example.com`, and the UI leaves
// itself out of the menu.

export interface ProductLink {
  id: string;
  url: string;
}

/** The products in the list, and the entries that are not `id=https://address`, to warn about. */
export function parseProducts(value: string | undefined): { products: ProductLink[]; invalid: string[] } {
  const products: ProductLink[] = [];
  const invalid: string[] = [];
  for (const entry of (value ?? "")
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean)) {
    const at = entry.indexOf("=");
    const id = entry.slice(0, at).trim();
    const url = URL.parse(entry.slice(at + 1).trim());
    if (at < 1 || !/^[a-z][a-z0-9-]*$/.test(id) || !url || (url.protocol !== "https:" && url.protocol !== "http:") || products.some((p) => p.id === id)) {
      invalid.push(entry);
      continue;
    }
    products.push({ id, url: url.origin + url.pathname.replace(/\/$/, "") });
  }
  return { products, invalid };
}
