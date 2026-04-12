/// <reference types="vite/client" />

declare module 'sm-crypto' {
  export const sm3: (input: string | number[] | Uint8Array, options?: { key?: string | number[] }) => string;
}
