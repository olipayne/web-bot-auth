import { describe, it, expect } from "vitest";
import {
  generateNonce,
  validateNonce,
  NONCE_LENGTH_IN_BYTES,
} from "../src/index";
import { b64Tou8, u8ToB64 } from "../src/base64";

describe("nonce", () => {
  describe("generateNonce", () => {
    it("should generate a base64 string", () => {
      const nonce = generateNonce();
      expect(typeof nonce).toBe("string");
      // Base64 regex pattern
      expect(() => b64Tou8(nonce)).not.toThrowError();
    });

    it("should generate nonce with correct length when decoded", () => {
      const nonce = generateNonce();
      const decoded = b64Tou8(nonce);
      expect(decoded.length).toBe(NONCE_LENGTH_IN_BYTES);
    });

    it("should generate unique nonces", () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      const nonce3 = generateNonce();
      expect(nonce1).not.toBe(nonce2);
      expect(nonce2).not.toBe(nonce3);
      expect(nonce1).not.toBe(nonce3);
    });
  });

  describe("validateNonce", () => {
    it("should validate correctly generated nonces", () => {
      const nonce = generateNonce();
      expect(validateNonce(nonce)).toBe(true);
    });

    it("should reject invalid base64 strings", () => {
      expect(validateNonce("not-base64!@#$")).toBe(false);
    });

    it("should reject empty string", () => {
      expect(validateNonce("")).toBe(false);
    });

    it("should reject nonces of incorrect length", () => {
      // Create a small base64 string
      const shortNonce = btoa("too short");
      expect(validateNonce(shortNonce)).toBe(false);

      // Create a long base64 string
      const longArray = new Uint8Array(NONCE_LENGTH_IN_BYTES + 10);
      crypto.getRandomValues(longArray);
      const longNonce = u8ToB64(longArray);
      expect(validateNonce(longNonce)).toBe(false);
    });

    it.each([[null], [undefined], [123], [{}], [[]], [true]])(
      "should handle invalid input type: %s",
      (invalidInput: unknown) => {
        expect(validateNonce(invalidInput as string)).toBe(false);
      }
    );

    it("should validate multiple generated nonces", () => {
      for (let i = 0; i < 10; i++) {
        const nonce = generateNonce();
        expect(validateNonce(nonce)).toBe(true);
      }
    });
  });
});
