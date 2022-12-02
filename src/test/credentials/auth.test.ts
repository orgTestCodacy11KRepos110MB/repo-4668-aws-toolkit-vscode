/*!
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

import * as assert from 'assert'
import * as sinon from 'sinon'
import * as vscode from 'vscode'
import {
    Auth,
    AuthNode,
    Connection,
    getSsoProfileKey,
    isIamConnection,
    ProfileStore,
    ssoAccountAccessScopes,
    SsoProfile,
} from '../../credentials/auth'
import { CredentialsStore } from '../../credentials/credentialsStore'
import { LoginManager } from '../../credentials/loginManager'
import { fromString } from '../../credentials/providers/credentials'
import { CredentialsProviderManager } from '../../credentials/providers/credentialsProviderManager'
import { SsoCredentialsProviderFactory } from '../../credentials/providers/ssoCredentialsProviderFactory'
import { SsoClient } from '../../credentials/sso/clients'
import { SsoToken } from '../../credentials/sso/model'
import { SsoAccessTokenProvider } from '../../credentials/sso/ssoAccessTokenProvider'
import { DefaultStsClient } from '../../shared/clients/stsClient'
import { ToolkitError } from '../../shared/errors'
import { toCollection } from '../../shared/utilities/asyncCollection'
import { FakeMemento } from '../fakeExtensionContext'
import { assertTreeItem } from '../shared/treeview/testUtil'
import { createTestWindow } from '../shared/vscode/window'
import { captureEvent } from '../testUtil'
import { FakeAwsContext } from '../utilities/fakeAwsContext'
import { stub } from '../utilities/stubber'

function createSsoProfile(props?: Partial<Omit<SsoProfile, 'type'>>): SsoProfile {
    return {
        type: 'sso',
        ssoRegion: 'us-east-1',
        startUrl: 'https://d-0123456789.awsapps.com/start',
        scopes: [],
        ...props,
    }
}

const ssoProfile = createSsoProfile()
const scopedSsoProfile = createSsoProfile({ scopes: ['foo'] })

describe('Auth', function () {
    const tokenProviders = new Map<string, ReturnType<typeof createTestTokenProvider>>()

    function createTestTokenProvider() {
        let token: SsoToken | undefined
        const provider = stub(SsoAccessTokenProvider)
        provider.getToken.callsFake(async () => token)
        provider.createToken.callsFake(
            async () => (token = { accessToken: '123', expiresAt: new Date(Date.now() + 1000000) })
        )
        provider.invalidate.callsFake(async () => (token = undefined))

        return provider
    }

    function getTestTokenProvider(...[profile]: ConstructorParameters<typeof SsoAccessTokenProvider>) {
        const key = getSsoProfileKey({ scopes: [], ...profile })
        const cachedProvider = tokenProviders.get(key)
        if (cachedProvider !== undefined) {
            return cachedProvider
        }

        const provider = createTestTokenProvider()
        tokenProviders.set(key, provider)

        return provider
    }

    async function invalidateConnection(profile: SsoProfile) {
        const provider = tokenProviders.get(getSsoProfileKey(profile))
        await provider?.invalidate()

        return provider
    }

    async function setupInvalidSsoConnection(auth: Auth, profile: SsoProfile) {
        const conn = await auth.createConnection(profile)
        await invalidateConnection(profile)

        return conn
    }

    let auth: Auth
    let store: ProfileStore
    let client: ReturnType<typeof stub<SsoClient>>
    let credentialManager: CredentialsProviderManager
    let loginManager: LoginManager

    afterEach(function () {
        tokenProviders.clear()
        sinon.restore()
    })

    beforeEach(function () {
        store = new ProfileStore(new FakeMemento())
        credentialManager = new CredentialsProviderManager()
        loginManager = new LoginManager(new FakeAwsContext(), new CredentialsStore())
        auth = new Auth(store, getTestTokenProvider, credentialManager, loginManager)
        client = stub(SsoClient)
        client.logout.resolves()

        sinon.replace(SsoClient, 'create', () => client)
        sinon.replace(DefaultStsClient.prototype, 'getCallerIdentity', async () => ({ Account: 'foo' }))
    })

    it('can create a new sso connection', async function () {
        const conn = await auth.createConnection(ssoProfile)
        assert.strictEqual(conn.type, 'sso')
    })

    it('can list connections', async function () {
        const conn1 = await auth.createConnection(ssoProfile)
        const conn2 = await auth.createConnection(scopedSsoProfile)
        assert.deepStrictEqual(
            await auth
                .listConnections()
                .map(c => c.id)
                .promise(),
            [conn1.id, conn2.id]
        )
    })

    it('can get a connection', async function () {
        const conn = await auth.createConnection(ssoProfile)
        assert.ok(await auth.getConnection({ id: conn.id }))
    })

    it('can delete a connection', async function () {
        const conn = await auth.createConnection(ssoProfile)
        await auth.deleteConnection({ id: conn.id })
        assert.strictEqual((await auth.listConnections().promise()).length, 0)
    })

    it('can delete an active connection', async function () {
        const conn = await auth.createConnection(ssoProfile)
        await auth.useConnection(conn)
        assert.ok(auth.activeConnection)
        await auth.deleteConnection(auth.activeConnection)
        assert.strictEqual((await auth.listConnections().promise()).length, 0)
        assert.strictEqual(auth.activeConnection, undefined)
    })

    it('throws when creating a duplicate connection', async function () {
        await auth.createConnection(ssoProfile)
        await assert.rejects(() => auth.createConnection(ssoProfile))
    })

    it('throws when using an invalid connection that was deleted', async function () {
        const conn = await setupInvalidSsoConnection(auth, ssoProfile)
        await auth.deleteConnection(conn)
        await assert.rejects(() => conn.getToken())
    })

    it('can logout and fires an event', async function () {
        const conn = await auth.createConnection(ssoProfile)
        const events = captureEvent(auth.onDidChangeActiveConnection)
        await auth.useConnection(conn)
        assert.strictEqual(auth.activeConnection?.id, conn.id)
        await auth.logout()
        assert.strictEqual(auth.activeConnection, undefined)
        assert.strictEqual(events.last, undefined)
    })

    describe('useConnection', function () {
        it('does not reauthenticate if the connection is invalid', async function () {
            const conn = await setupInvalidSsoConnection(auth, ssoProfile)
            await auth.useConnection(conn)
            assert.strictEqual(auth.activeConnection?.state, 'invalid')
        })

        it('fires an event', async function () {
            const conn = await auth.createConnection(ssoProfile)
            const events = captureEvent(auth.onDidChangeActiveConnection)
            await auth.useConnection(conn)
            assert.strictEqual(events.emits[0]?.id, conn.id)
        })
    })

    it('can login and fires an event', async function () {
        const conn = await auth.createConnection(ssoProfile)
        const events = captureEvent(auth.onDidChangeActiveConnection)
        await auth.useConnection(conn)
        assert.strictEqual(auth.activeConnection?.id, conn.id)
        assert.strictEqual(auth.activeConnection.state, 'valid')
        assert.strictEqual(events.emits[0]?.id, conn.id)
    })

    it('uses the persisted connection if available (valid)', async function () {
        const conn = await auth.createConnection(ssoProfile)
        await store.setCurrentProfileId(conn.id)
        await auth.restorePreviousSession()
        assert.strictEqual(auth.activeConnection?.state, 'valid')
    })

    it('uses the persisted connection if available (invalid)', async function () {
        const conn = await setupInvalidSsoConnection(auth, ssoProfile)
        tokenProviders.get(getSsoProfileKey(ssoProfile))?.getToken.resolves(undefined)
        await store.setCurrentProfileId(conn.id)
        await auth.restorePreviousSession()
        assert.strictEqual(auth.activeConnection?.state, 'invalid')
    })

    async function runExpiredConnectionFlow(conn: Connection, selection: string | RegExp) {
        const testWindow = createTestWindow()
        sinon.replace(vscode, 'window', testWindow)

        const result = conn.type === 'sso' ? conn.getToken() : conn.getCredentials()
        const message = await testWindow.waitForMessage(/connection is invalid or expired/i)
        message.selectItem(selection)

        return result
    }

    describe('SSO Connections', function () {
        it('creates a new token if one does not exist', async function () {
            const conn = await auth.createConnection(ssoProfile)
            const provider = tokenProviders.get(getSsoProfileKey(ssoProfile))
            assert.deepStrictEqual(await provider?.getToken(), await conn.getToken())
        })

        it('prompts the user if the token is invalid or expired', async function () {
            const conn = await setupInvalidSsoConnection(auth, ssoProfile)
            const token = await runExpiredConnectionFlow(conn, /yes/i)
            assert.notStrictEqual(token, undefined)
        })

        it('using the connection lazily updates the state', async function () {
            const conn = await auth.createConnection(ssoProfile)
            await auth.useConnection(conn)
            await invalidateConnection(ssoProfile)

            const token = runExpiredConnectionFlow(conn, /no/i)
            await assert.rejects(token, ToolkitError)

            assert.strictEqual(auth.activeConnection?.state, 'invalid')
        })
    })

    describe('AuthNode', function () {
        it('shows a message to create a connection if no connections exist', async function () {
            const node = new AuthNode(auth)
            await assertTreeItem(node, { label: 'Connect to AWS to Get Started...' })
        })

        it('shows a login message if not connected', async function () {
            await auth.createConnection(ssoProfile)
            const node = new AuthNode(auth)
            await assertTreeItem(node, { label: 'Select a connection...' })
        })

        it('shows the connection if valid', async function () {
            const node = new AuthNode(auth)
            const conn = await auth.createConnection(ssoProfile)
            await auth.useConnection(conn)
            await assertTreeItem(node, { label: `Connected with ${conn.label}` })
        })

        it('shows an error if the connection is invalid', async function () {
            const node = new AuthNode(auth)
            const conn = await setupInvalidSsoConnection(auth, ssoProfile)
            tokenProviders.get(getSsoProfileKey(ssoProfile))?.getToken.resolves(undefined)
            await auth.useConnection(conn)
            await assertTreeItem(node, { description: 'expired or invalid, click to authenticate' })
        })
    })

    describe('Linked Connections', function () {
        const linkedSsoProfile = createSsoProfile({ scopes: ssoAccountAccessScopes })
        const accountRoles = [
            { accountId: '1245678910', roleName: 'foo' },
            { accountId: '9876543210', roleName: 'foo' },
            { accountId: '9876543210', roleName: 'bar' },
        ]

        beforeEach(function () {
            client.listAccounts.returns(
                toCollection(async function* () {
                    yield [{ accountId: '1245678910' }, { accountId: '9876543210' }]
                })
            )

            client.listAccountRoles.callsFake(req =>
                toCollection(async function* () {
                    yield accountRoles.filter(i => i.accountId === req.accountId)
                })
            )

            client.getRoleCredentials.resolves({
                accessKeyId: 'xxx',
                secretAccessKey: 'xxx',
                expiration: new Date(Date.now() + 1000000),
            })

            credentialManager.addProviderFactory(new SsoCredentialsProviderFactory(auth))
        })

        it('lists linked conections for SSO connections', async function () {
            await auth.createConnection(linkedSsoProfile)
            const connections = await auth.listConnections().promise()
            assert.deepStrictEqual(
                connections.map(c => c.type),
                ['sso', 'iam', 'iam', 'iam']
            )
        })

        it('caches linked conections when the source connection becomes invalid', async function () {
            await auth.createConnection(linkedSsoProfile)
            await auth.listConnections().promise()
            await invalidateConnection(linkedSsoProfile)

            const connections = await auth.listConnections().promise()
            assert.deepStrictEqual(
                connections.map(c => c.type),
                ['sso', 'iam', 'iam', 'iam']
            )
        })

        it('removes linked connections when the source connection is deleted', async function () {
            const conn = await auth.createConnection(linkedSsoProfile)
            await auth.listConnections().promise()
            await auth.deleteConnection(conn)

            assert.deepStrictEqual(await auth.listConnections().promise(), [])
        })

        it('prompts the user to reauthenticate if the source connection becomes invalid', async function () {
            const source = await auth.createConnection(linkedSsoProfile)
            await auth.listConnections().promise()

            const conn = await auth.listConnections().find(c => isIamConnection(c) && c.id.includes('sso'))
            assert.ok(conn)
            await auth.useConnection(conn)
            await invalidateConnection(linkedSsoProfile)
            loginManager.store.invalidateCredentials(fromString(conn.id))

            await runExpiredConnectionFlow(conn, /yes/i)
            assert.strictEqual(auth.getConnectionState(source), 'valid')
            assert.strictEqual(auth.getConnectionState(conn), 'valid')
        })
    })
})
