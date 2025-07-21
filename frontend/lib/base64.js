// deno-lint-ignore-file
// deno-fmt-ignore-file
// @ts-nocheck
// @ts-self-types="./base64.d.ts"
function base64Decode(input){return Uint8Array.fromBase64(input,{alphabet:"base64url",lastChunkHandling:"loose"})}function base64Encode(input){return input.toBase64({alphabet:"base64url",omitPadding:!0})}export{base64Decode,base64Encode};