import fs from 'fs';
import path from 'path';
import {utils, Wallet} from 'ethers';
import {auditor, util} from '@jovijovi/pedrojs-common';
import {CombinationKey, Remove0xPrefix} from './ksutil';
import {CacheType, ksCache} from './cache';
import {RetryInterval, RetryTimes} from './params';
import * as errors from './errors';

const defaultKeystoreDir = 'keystore';

// getCipherText returns cipher text from key file
async function getCipherText(address: string, keystoreType: string): Promise<string> {
	const keyPath = path.resolve(defaultKeystoreDir, keystoreType, address.toLowerCase());
	auditor.Check(fs.existsSync(keyPath), errors.ErrorKeyFileNotExist);

	return await util.retry.Run((): string => {
		return fs.readFileSync(keyPath, 'utf8');
	}, RetryTimes, RetryInterval);
}

// GetWallet returns wallet from cipherText
export async function GetWallet(cipherText: string, passphrase: string): Promise<Wallet> {
	return await Wallet.fromEncryptedJson(cipherText, passphrase);
}

// InspectKeystoreWallet returns the wallet from keystore and the keystore filename must match the lowercase address
export async function InspectKeystoreWallet(address: string, keystoreType: string, passphrase: string, isBase64 = true, useCache = true): Promise<Wallet> {
	auditor.Check(utils.isAddress(address), errors.ErrorInvalidAddress);

	const key = CombinationKey([CacheType.Wallet, address]);
	if (useCache) {
		if (ksCache.has(key)) {
			return ksCache.get(key);
		}
	}

	const cipherText = await getCipherText(address, keystoreType);
	const wallet = await GetWallet(cipherText, isBase64 ? new TextDecoder().decode(utils.base64.decode(passphrase)) : passphrase);
	auditor.Check(address.toLowerCase() === wallet.address.toLowerCase(), `wallet address doesn't match`);

	if (useCache) {
		ksCache.set(key, wallet);
	}

	return wallet;
}

// GetPK returns wallet private key from cipherText
export async function GetPK(cipherText: string, passphrase: string): Promise<string> {
	const wallet = await GetWallet(cipherText, passphrase);
	return wallet.privateKey;
}

// InspectKeystorePK returns the address PK from keystore
// and the keystore filename must match the lowercase address
export async function InspectKeystorePK(address: string, keystoreType: string, passphrase: string, isBase64 = true, useCache = true): Promise<string> {
	auditor.Check(utils.isAddress(address), errors.ErrorInvalidAddress);

	const key = CombinationKey([CacheType.PK, address]);
	if (useCache) {
		if (ksCache.has(key)) {
			return ksCache.get(key);
		}
	}

	const cipherText = await getCipherText(address, keystoreType);
	const pk = await GetPK(cipherText, isBase64 ? new TextDecoder().decode(utils.base64.decode(passphrase)) : passphrase);
	auditor.Check(utils.isHexString(pk), errors.ErrorInvalidPK);

	if (useCache) {
		ksCache.set(key, pk);
	}

	return pk;
}

// InspectKeystorePKWithoutPrefix returns the address PK (without prefix '0x) from keystore
// and the keystore filename must match the lowercase address
export async function InspectKeystorePKWithoutPrefix(address: string, keystoreType: string, passphrase: string, isBase64 = true, useCache = true): Promise<string> {
	const key = CombinationKey([CacheType.PKWithoutPrefix, address]);
	if (useCache) {
		if (ksCache.has(key)) {
			return ksCache.get(key);
		}
	}

	// Remove '0x' prefix of PK
	const pk = Remove0xPrefix(await InspectKeystorePK(address, keystoreType, passphrase, isBase64));

	if (useCache) {
		ksCache.set(key, pk);
	}

	return pk;
}

export * as ksUtil from './ksutil';
export * as types from './types';
export {ksCache} from './cache';
export * as errors from './errors';
