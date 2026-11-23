import { buffer } from 'node:stream/consumers';
import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';

const fixture = JSON.parse(await buffer(process.stdin));
const { expectedOrigin, expectedRPID } = fixture;

async function registration() {
  const { response, expectedChallenge, algorithm, conditional } = fixture.registration;
  const result = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    supportedAlgorithmIDs: [algorithm],
    requireUserPresence: !conditional,
    requireUserVerification: true,
  });
  if (!result.verified) {
    throw new Error('SimpleWebAuthn refused the registration');
  }
  return result.registrationInfo;
}

async function assertion({ response, expectedChallenge }, credential) {
  let result;
  try {
    result = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      credential,
      requireUserVerification: true,
    });
  } catch (error) {
    return { verified: false, detail: error.message };
  }
  if (!result.verified) {
    return { verified: false, detail: 'SimpleWebAuthn refused the assertion' };
  }
  const { credentialID, newCounter, userVerified, credentialDeviceType, credentialBackedUp } = result.authenticationInfo;
  return {
    verified: true,
    id: credentialID,
    counter: newCounter,
    userVerified,
    backupEligible: credentialDeviceType === 'multiDevice',
    backedUp: credentialBackedUp,
  };
}

const { credential, fmt, credentialDeviceType, credentialBackedUp } = await registration();
const assertions = [];
for (const request of fixture.assertions) {
  assertions.push(await assertion(request, credential));
}
process.stdout.write(JSON.stringify({
  registration: {
    id: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    format: fmt,
    backupEligible: credentialDeviceType === 'multiDevice',
    backedUp: credentialBackedUp,
  },
  assertions,
}));
