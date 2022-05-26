/*!
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

import * as vscode from 'vscode'
import {
    AccountDetails,
    AuthenticationProvider,
    AuthenticationSessionsChangeEvent,
    Session,
} from '../credentials/authentication'
import { getRegistrationCache } from '../credentials/sso/cache'
import { ClientRegistration, SsoToken } from '../credentials/sso/model'
import { SsoAccessTokenProvider } from '../credentials/sso/ssoAccessTokenProvider'
import { ConnectedCawsClient, createClient, Person } from '../shared/clients/cawsClient'
import { getLogger } from '../shared/logger'
import { createSecretsCache, KeyedCache, mapCache } from '../shared/utilities/cacheUtils'
import { assertHasProps, isNonNullable } from '../shared/utilities/tsUtils'

const CAWS_SONO_PROFILE = {
    startUrl: 'https://d-9067642ac7.awsapps.com/start',
    region: 'us-east-1',
    scopes: ['sso:account:access'],
}

async function verifySession(token: string, id?: string | Person) {
    const client = await createClient()
    await client.setCredentials(token, id)

    return client.verifySession()
}

interface SonoAccess {
    readonly token: SsoToken
    readonly registration: ClientRegistration
    readonly region: typeof CAWS_SONO_PROFILE['region']
    readonly startUrl: typeof CAWS_SONO_PROFILE['startUrl']
}

interface UserMetadata extends Person {
    readonly canAutoConnect?: boolean
}

// Secrets stored on the macOS keychain appear as individual entries for each key
// This is fine so long as the user has only a few accounts. Otherwise this should
// store secrets as a map.
export class CawsAuthStorage {
    private static readonly USERS_MEMENTO_KEY = 'caws.users'
    private static readonly SECRETS_KEY = 'caws.authtokens'

    public constructor(private readonly memento: vscode.Memento, private readonly secrets: vscode.SecretStorage) {}

    public getUser(id: string): UserMetadata | undefined {
        return this.listUsers()[id]
    }

    public listUsers(): Record<string, UserMetadata> {
        return this.memento.get<Record<string, UserMetadata>>(CawsAuthStorage.USERS_MEMENTO_KEY, {})
    }

    public async deleteUser(id: string): Promise<void> {
        const userdata = this.memento.get<Record<string, UserMetadata>>(CawsAuthStorage.USERS_MEMENTO_KEY, {})
        delete userdata[id]
        await this.memento.update(CawsAuthStorage.USERS_MEMENTO_KEY, userdata)
        await this.getTokenCache().clear(id)
    }

    public async updateUser(id: string, metadata?: UserMetadata): Promise<void> {
        const userdata = this.memento.get<Record<string, UserMetadata>>(CawsAuthStorage.USERS_MEMENTO_KEY, {})

        await this.memento.update(CawsAuthStorage.USERS_MEMENTO_KEY, {
            ...userdata,
            [id]: { ...userdata[id], ...metadata },
        })
    }

    private getTokenCache(): KeyedCache<SonoAccess> {
        function read(data: string): SonoAccess {
            return JSON.parse(data, (key, value) => {
                if (key === 'expiresAt') {
                    return new Date(value)
                } else {
                    return value
                }
            })
        }

        function write(data: SonoAccess): string {
            return JSON.stringify(data, (key, value) => {
                if (key === 'expiresAt' && value instanceof Date) {
                    return value.toISOString()
                } else if (value !== undefined) {
                    return value
                }
            })
        }

        const logger = (message: string) => getLogger().debug(`SSO token cache (CAWS): ${message}`)
        const cache = mapCache(createSecretsCache(this.secrets, logger), read, write)
        const getKey = (id: string) => `${CawsAuthStorage.SECRETS_KEY}.${id}`

        return {
            save: (id, data) => cache.save(getKey(id), data),
            load: id => cache.load(getKey(id)),
            clear: id => cache.clear(getKey(id)),
        }
    }

    public getTokenProvider(id?: string): SsoAccessTokenProvider {
        const profile = { ...CAWS_SONO_PROFILE, identifier: id }
        const provider = new SsoAccessTokenProvider(profile, {
            token: this.getTokenCache(),
            registration: getRegistrationCache(),
        })

        return provider
    }

    public async getPat(id: string): Promise<string | undefined> {
        return this.secrets.get(`caws.pat.${id}`)
    }

    public async storePat(id: string, pat: string): Promise<void> {
        await this.secrets.store(`caws.pat.${id}`, pat)
    }
}

export interface CawsAccount extends AccountDetails {
    readonly metadata: UserMetadata
}
export type CawsSession = Session<string, CawsAccount>

export class CawsAuthenticationProvider implements AuthenticationProvider<string, CawsAccount> {
    private readonly _onDidChangeSessions = new vscode.EventEmitter<AuthenticationSessionsChangeEvent<CawsSession>>()
    public readonly onDidChangeSessions = this._onDidChangeSessions.event

    private readonly sessions = new Map<string, CawsSession>()
    private readonly sessionExpiration = new Map<string, Date>()
    private sessionCounter = 0

    public constructor(protected readonly storage: CawsAuthStorage, private readonly verify = verifySession) {}

    public listAccounts(): CawsAccount[] {
        return Object.entries(this.storage.listUsers()).map(([id, data]) => ({
            id,
            label: data.displayName,
            metadata: data,
        }))
    }

    /**
     * Runs through a full SSO flow.
     *
     * This should only ever be called through an explicit user action.
     */
    public async createAccount(): Promise<CawsAccount> {
        const tokenProvider = this.storage.getTokenProvider()
        const token = await tokenProvider.createToken(async token => {
            const person = await this.verify(token.accessToken)
            await this.storage.updateUser(person.userId, { ...person, canAutoConnect: true })

            return person.userId
        })

        // XXX: registrations can only be used for refresh grants with the new OIDC token
        getRegistrationCache()
            .clear(CAWS_SONO_PROFILE)
            .then(() => {
                getLogger().debug('CAWS: cleared client registration to prevent it being re-used')
            })

        assertHasProps(token, 'identity')
        const user = this.storage.getUser(token.identity)

        if (!user) {
            throw new Error()
        }

        return {
            id: token.identity,
            label: user.displayName,
            metadata: user,
        }
    }

    /**
     * This method will largely go unused unless multi-tenant auth becomes a requirement.
     */
    public listSessions(): CawsSession[] {
        const expired = Array.from(this.sessions.values()).filter(s => this.isSessionExpired(s))
        expired.forEach(({ id }) => getLogger().debug(`CAWS: removing expired session: ${id}`))

        this.deleteSession(...expired)
        return Array.from(this.sessions.values())
    }

    private async login(account: Pick<AccountDetails, 'id'>): Promise<CawsSession> {
        const tokenProvider = this.storage.getTokenProvider(account.id)
        const token = await tokenProvider.getToken()

        if (!token) {
            // Prompter user to login again here?
            throw new Error('Account has no access token')
        }

        try {
            const stored = this.storage.getUser(account.id)
            const person = await this.verify(token.accessToken, stored ?? account.id)
            const sessionId = `session-${(this.sessionCounter += 1)}`
            const updatedPerson = { ...person, canAutoConnect: true }
            this.sessionExpiration.set(sessionId, token.expiresAt)

            if (!stored || JSON.stringify(stored) !== JSON.stringify(updatedPerson)) {
                await this.storage.updateUser(person.userId, updatedPerson)
            }

            return {
                id: sessionId,
                accessDetails: token.accessToken,
                accountDetails: { id: person.userId, label: person.displayName, metadata: updatedPerson },
            }
        } catch (err) {
            getLogger().debug(`CAWS: failed to login (will clear existing secrets): ${(err as Error).message}`)
            tokenProvider.invalidate()
            throw err
        }
    }

    /**
     * Creating a new session is the equivalent to logging into the selected account, which may involve
     * some sort of auth flow
     *
     * It's important to note that creating a session does not require knowledge of an account.
     * Usually with an SSO flow we won't know account details until after a session has been created.
     */
    public async createSession(account: CawsAccount): Promise<CawsSession> {
        const session = await this.login(account)

        this.sessions.set(session.id, session)
        this._onDidChangeSessions.fire({ added: [session] })

        return session
    }

    public async deleteSession(...sessions: CawsSession[]): Promise<void> {
        const removed = (
            await Promise.all(
                sessions.map(async ({ id, accountDetails }) => {
                    const previous = this.sessions.get(id)
                    const isExpired = this.isSessionExpired({ id })
                    this.sessions.delete(id)
                    this.sessionExpiration.delete(id)

                    if (previous && !isExpired) {
                        await this.storage.updateUser(accountDetails.id, {
                            ...previous.accountDetails.metadata,
                            canAutoConnect: false,
                        })
                    }

                    return previous
                })
            )
        ).filter(isNonNullable)

        if (removed.length > 0) {
            this._onDidChangeSessions.fire({ removed })
        }
    }

    public async deleteAccount(account: CawsAccount): Promise<void> {
        await this.storage.deleteUser(account.id)
    }

    public getActiveSession(): CawsSession | undefined {
        return this.listSessions()[0]
    }

    // Get rid of this? Not sure where to put PAT code.
    public async getPat(client: ConnectedCawsClient): Promise<string> {
        const stored = await this.storage.getPat(client.identity.id)

        if (stored) {
            return stored
        }

        const resp = await client.createAccessToken({ name: 'aws-toolkits-vscode-token', expires: undefined })
        await this.storage.storePat(client.identity.id, resp.secret)

        return resp.secret
    }

    private isSessionExpired(session: Pick<CawsSession, 'id'>): boolean {
        const expiration = this.sessionExpiration.get(session.id)

        return !!expiration && expiration.getTime() - 60000 < Date.now()
    }

    private static instance: CawsAuthenticationProvider

    public static fromContext(ctx: Pick<vscode.ExtensionContext, 'secrets' | 'globalState'>) {
        return (this.instance ??= new this(new CawsAuthStorage(ctx.globalState, ctx.secrets)))
    }
}