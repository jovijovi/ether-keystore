import {keystore} from '../lib';
import assert from 'assert';
import {utils, Wallet,} from 'ethers';
import fs from 'fs';
import path from "path";
import {randomFillSync} from "crypto";

let mockAddress = '';
const mockPassphraseBase64 = 'MTIzNDU2';
const mockPassphrasePlain = '123456';

beforeAll(async () => {
	const wallet = Wallet.createRandom({
		extraEntropy: randomFillSync(new Uint8Array(64)),
	});

	const jsonWallet = await wallet.encrypt(mockPassphrasePlain);

	const path1 = path.resolve('keystore', 'miner');
	if (!fs.existsSync(path1)) {
		fs.mkdirSync(path1, {recursive: true});
	}

	const path2 = path.resolve('keystore', 'fee');
	if (!fs.existsSync(path2)) {
		fs.mkdirSync(path2, {recursive: true});
	}

	const keyPath1 = path.resolve('keystore', 'miner', wallet.address.toLowerCase());
	const keyPath2 = path.resolve('keystore', 'fee', wallet.address.toLowerCase());

	fs.writeFileSync(keyPath1, jsonWallet);
	fs.copyFileSync(keyPath1, keyPath2);

	mockAddress = wallet.address.toLowerCase();
}, 5000)

test('InspectKeystorePK', async () => {
	const pk = await keystore.InspectKeystorePK(mockAddress.toLowerCase(), keystore.types.KeystoreTypeMiner, mockPassphraseBase64);
	console.debug("PK=", pk);

	const address = utils.computeAddress(pk);
	console.debug("Computed address=", address);

	assert.strictEqual(mockAddress.toLowerCase(), address.toLowerCase());
}, 10000)

test('InspectKeystorePK with plain passphrase', async () => {
	const pk = await keystore.InspectKeystorePK(mockAddress.toLowerCase(), keystore.types.KeystoreTypeMiner, mockPassphrasePlain, false, false);
	console.debug("PK=", pk);

	const address = utils.computeAddress(pk);
	console.debug("Computed address=", address);

	assert.strictEqual(mockAddress.toLowerCase(), address.toLowerCase());
}, 10000)

test('InspectKeystorePKWithoutPrefix', async () => {
	const pk = await keystore.InspectKeystorePKWithoutPrefix(mockAddress.toLowerCase(), keystore.types.KeystoreTypeFee, mockPassphraseBase64);
	console.debug("PK=", pk);

	const wallet = new Wallet(pk);
	console.debug("Wallet address=", wallet.address);

	assert.strictEqual(mockAddress.toLowerCase(), wallet.address.toLowerCase());
}, 10000)

test('InspectKeystoreWallet', async () => {
	const wallet = await keystore.InspectKeystoreWallet(mockAddress.toLowerCase(), keystore.types.KeystoreTypeFee, mockPassphraseBase64);
	console.debug("Wallet address=", wallet.address);
	assert.strictEqual(mockAddress.toLowerCase(), wallet.address.toLowerCase());
}, 10000)

test('InspectKeystoreWallet with plain passphrase', async () => {
	const wallet = await keystore.InspectKeystoreWallet(mockAddress.toLowerCase(), keystore.types.KeystoreTypeFee, mockPassphrasePlain, false, false);
	console.debug("Wallet address=", wallet.address);
	assert.strictEqual(mockAddress.toLowerCase(), wallet.address.toLowerCase());
}, 10000)

test('Keystore Cache', async () => {
	const key = keystore.ksUtil.CombinationKey(['hello', 'world']);
	keystore.ksCache.set(key, 42);

	const value = keystore.ksCache.get(key);
	console.debug("Cached Value=", value);

	assert.strictEqual(value, 42);
})

test('With Cache', async () => {
	for (let i = 0; i < 10; i++) {
		const pk1 = await keystore.InspectKeystorePK(mockAddress.toLowerCase(), keystore.types.KeystoreTypeMiner, mockPassphraseBase64);
		console.debug("PK1=", pk1);

		const pk2 = await keystore.InspectKeystorePKWithoutPrefix(mockAddress.toLowerCase(), keystore.types.KeystoreTypeFee, mockPassphraseBase64);
		console.debug("PK2=", pk2);

		const wallet = await keystore.InspectKeystoreWallet(mockAddress.toLowerCase(), keystore.types.KeystoreTypeFee, mockPassphraseBase64);
		console.debug("Wallet= address", wallet.address);
	}
})

test('Without Cache', async () => {
	for (let i = 0; i < 3; i++) {
		const pk1 = await keystore.InspectKeystorePK(mockAddress.toLowerCase(), keystore.types.KeystoreTypeMiner, mockPassphraseBase64, true, false);
		console.debug("PK1=", pk1);

		const pk2 = await keystore.InspectKeystorePKWithoutPrefix(mockAddress.toLowerCase(), keystore.types.KeystoreTypeFee, mockPassphraseBase64, true, false);
		console.debug("PK2=", pk2);

		const wallet = await keystore.InspectKeystoreWallet(mockAddress.toLowerCase(), keystore.types.KeystoreTypeFee, mockPassphraseBase64, true, false);
		console.debug("Wallet= address", wallet.address);
	}
}, 100000)

test('Remove0xPrefix', async () => {
	const empty = keystore.ksUtil.Remove0xPrefix('');
	assert.strictEqual(empty, '');

	const foo = keystore.ksUtil.Remove0xPrefix('foo');
	assert.strictEqual(foo, 'foo');
})

test('ERROR: invalid address', async () => {
	try {
		const wallet = await keystore.InspectKeystoreWallet('foo', keystore.types.KeystoreTypeFee, mockPassphraseBase64);
		console.debug("Wallet address=", wallet.address);
	} catch (e) {
		console.error(e);
		assert.strictEqual(e.message, keystore.errors.ErrorInvalidAddress);
	}
}, 10000)

test('ERROR: key file not exist', async () => {
	try {
		const wallet = await keystore.InspectKeystoreWallet(mockAddress.toLowerCase(), 'not_exist', mockPassphraseBase64);
		console.debug("Wallet address=", wallet.address);
	} catch (e) {
		console.error(e);
		assert.strictEqual(e.message, keystore.errors.ErrorKeyFileNotExist);
	}
}, 10000)

test('ERROR: invalid password', async () => {
	try {
		const wallet = await keystore.InspectKeystoreWallet(mockAddress.toLowerCase(), keystore.types.KeystoreTypeFee, 'invalid_password');
		console.debug("Wallet address=", wallet.address);
	} catch (e) {
		console.error(e);
		assert.strictEqual(e.message, keystore.errors.ErrorInvalidPassword);
	}
}, 10000)
