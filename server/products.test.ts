import { describe, expect, it } from "vitest";
import { parseProducts } from "./products.ts";

describe("OPENASY_PRODUCTS", () => {
  it("reads each product and its address", () => {
    expect(parseProducts(" vpn=https://vpn.example.com/ , infrastructure=https://example.com/infra/")).toEqual({
      products: [
        { id: "vpn", url: "https://vpn.example.com" },
        { id: "infrastructure", url: "https://example.com/infra" },
      ],
      invalid: [],
    });
  });

  it("is empty when unset", () => {
    expect(parseProducts(undefined)).toEqual({ products: [], invalid: [] });
    expect(parseProducts("")).toEqual({ products: [], invalid: [] });
  });

  it("leaves out entries that are not id=address, and repeats", () => {
    const { products, invalid } = parseProducts(
      "vpn,=https://a.example.com,Logs=https://b.example.com,logs=ftp://c.example.com,logs=not a url,vpn=https://vpn.example.com,vpn=https://other.example.com",
    );
    expect(products).toEqual([{ id: "vpn", url: "https://vpn.example.com" }]);
    expect(invalid).toEqual([
      "vpn",
      "=https://a.example.com",
      "Logs=https://b.example.com",
      "logs=ftp://c.example.com",
      "logs=not a url",
      "vpn=https://other.example.com",
    ]);
  });
});
