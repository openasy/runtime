import { messageProblems } from "@openasy/ui";
import { describe, expect, it } from "vitest";
import de from "./messages/de.json";
import en from "./messages/en.json";
import tr from "./messages/tr.json";

describe("page words", () => {
  it("has every message in every language, with the same placeholders", () => {
    expect(messageProblems({ en, tr, de })).toEqual([]);
  });
});
