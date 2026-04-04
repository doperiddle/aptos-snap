import nacl from 'tweetnacl';
import { deriveKeyPair } from './privateKey';
import { assertInput, assertConfirmation, assertAllStrings, assertIsString, assertIsBoolean, assertIsArray, bytesToHex, hexToBytes } from './utils';
import { renderGetPublicKey, renderSignTransaction, renderSignAllTransactions, renderSignMessage } from './ui';

module.exports.onRpcRequest = async ({ origin, request }) => {
  if (
    !origin ||
    (
      !origin.match(/^https:\/\/(?:[a-zA-Z0-9-]+\.)?risewallet\.io$/) &&
      !origin.match(/^https:\/\/(?:[a-zA-Z0-9-]+\.)?risewallet\.dev$/)
    )
  ) {
    throw new Error('Invalid origin');
  }

  let dappHost;
  try {
    const dappOriginParam = request?.params?.origin;
    const dappOrigin = (typeof dappOriginParam === 'string' && dappOriginParam) ? dappOriginParam : origin;
    dappHost = new URL(dappOrigin).host;
  } catch {
    throw new Error('Invalid origin parameter.');
  }

  switch (request.method) {
    case 'getPublicKey': {
      const { derivationPath, confirm = false } = request.params || {};

      assertIsBoolean(confirm);

      const keyPair = await deriveKeyPair(derivationPath);

      const pubkey = bytesToHex(keyPair.publicKey);

      if (confirm) {
        const accepted = await renderGetPublicKey(dappHost, pubkey);
        assertConfirmation(accepted);
      }

      return pubkey;
    }
    case 'signTransaction': {
      const { derivationPath, message } = request.params || {};

      assertInput(message);
      assertIsString(message);

      const keyPair = await deriveKeyPair(derivationPath);

      const accepted = await renderSignTransaction(dappHost, message);
      assertConfirmation(accepted);

      const messageBytes = hexToBytes(message);
      const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);

      return {
        publicKey: bytesToHex(keyPair.publicKey),
        signature: bytesToHex(signature)
      };
    }
    case 'signAllTransactions': {
      const { derivationPath, messages } = request.params || {};

      assertInput(messages);
      assertIsArray(messages);
      assertInput(messages.length);
      assertAllStrings(messages);

      if (messages.length > 100) {
        throw {
          code: -32000,
          message: 'Batch signing limited to maximum of 100 messages.'
        };
      }

      const keyPair = await deriveKeyPair(derivationPath);

      const accepted = await renderSignAllTransactions(dappHost, messages);
      assertConfirmation(accepted);

      const signatures = messages
        .map((message) => hexToBytes(message))
        .map((message) => nacl.sign.detached(message, keyPair.secretKey))
        .map((signature) => bytesToHex(signature));

      return {
        publicKey: bytesToHex(keyPair.publicKey),
        signatures
      };
    }
    case 'signMessage': {
      const { derivationPath, message } = request.params || {};

      assertInput(message);
      assertIsString(message);

      const keyPair = await deriveKeyPair(derivationPath);

      const messageBytes = hexToBytes(message);

      let decodedMessage = '';
      try {
        decodedMessage = (new TextDecoder()).decode(messageBytes);
      } catch (error) {
        decodedMessage = 'Unable to decode message';
      }

      const accepted = await renderSignMessage(dappHost, decodedMessage);
      assertConfirmation(accepted);

      const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);

      return {
        publicKey: bytesToHex(keyPair.publicKey),
        signature: bytesToHex(signature)
      };
    }
    default:
      throw {
        code: 4200,
        message: 'The requested method is not supported.'
      };
  }
};
